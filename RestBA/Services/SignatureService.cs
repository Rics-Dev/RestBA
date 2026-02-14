using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.Extensions.Options;
using RestBA.Options;

namespace RestBA.Services;

public class SignatureService
{
    private const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    private const string DsNs = "http://www.w3.org/2000/09/xmldsig#";
    private const string ExcC14NAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string RsaSha256Algorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private const string Sha256DigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private readonly CertificateOptions _certOptions;
    private readonly ILogger<SignatureService> _logger;
    private X509Certificate2? _certificate;

    public SignatureService(IOptions<CertificateOptions> certOptions, ILogger<SignatureService> logger)
    {
        _certOptions = certOptions.Value;
        _logger = logger;
        LoadCertificate();
    }

    private void LoadCertificate()
    {
        try
        {
            if (File.Exists(_certOptions.KeystorePath))
            {
                _certificate = X509CertificateLoader.LoadPkcs12FromFile(
                    _certOptions.KeystorePath, _certOptions.KeystorePassword,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                _logger.LogInformation("Certificate loaded successfully");
            }
            else
            {
                _logger.LogWarning("Certificate file not found at {Path}", _certOptions.KeystorePath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load certificate");
        }
    }

    public string SignMXDocument(string documentContent)
    {
        if (_certificate == null)
        {
            throw new InvalidOperationException("Certificate not loaded");
        }

        try
        {
            // Use PreserveWhitespace = true for consistent canonicalization
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(documentContent);

            var documentElement = xmlDoc.SelectSingleNode("//*[local-name()='Document']") as XmlElement
                ?? throw new InvalidOperationException("Document element not found");

            var appHdrElement = xmlDoc.SelectSingleNode("//*[local-name()='AppHdr']") as XmlElement
                ?? throw new InvalidOperationException("AppHdr element not found");

            var signatureId = "_" + Guid.NewGuid().ToString();
            var keyInfoId = "_" + Guid.NewGuid().ToString();
            var signedPropsId = "_" + Guid.NewGuid().ToString() + "-signedprops";

            // 1. Canonicaliser l'élément Document (référence sans URI)
            var documentCanonical = CanonicalizeElement(documentElement);
            var documentDigest = ComputeSha256Digest(documentCanonical);

            // 2. Construire le KeyInfo avec X509IssuerSerial uniquement
            var keyInfoElement = BuildKeyInfoElement(xmlDoc, keyInfoId);
            var keyInfoCanonical = CanonicalizeElement(keyInfoElement);
            var keyInfoDigest = ComputeSha256Digest(keyInfoCanonical);

            // 3. Construire l'élément SignedProperties XAdES avec SigningTime
            var signedPropsElement = BuildSignedPropertiesElement(xmlDoc, signedPropsId);
            var signedPropsCanonical = CanonicalizeElement(signedPropsElement);
            var signedPropsDigest = ComputeSha256Digest(signedPropsCanonical);

            // 4. Construire le SignedInfo avec les 3 références
            var signedInfoElement = BuildSignedInfoElement(
                xmlDoc, keyInfoId, keyInfoDigest, signedPropsId, signedPropsDigest, documentDigest);

            // 5. Canonicaliser SignedInfo et calculer la signature
            var signedInfoCanonical = CanonicalizeElement(signedInfoElement);
            var signatureValue = ComputeRsaSha256Signature(signedInfoCanonical);

            // 6. Assembler la signature complète
            var signatureElement = BuildSignatureElement(
                xmlDoc, signatureId, signedInfoElement, signatureValue,
                keyInfoElement, signedPropsElement, signedPropsId, signatureId);

            // 7. Insérer dans AppHdr/Sgntr
            var sgntrElement = xmlDoc.CreateElement("Sgntr", appHdrElement.NamespaceURI);
            sgntrElement.AppendChild(signatureElement);
            appHdrElement.AppendChild(sgntrElement);

            // Return the XML directly — do NOT reformat/minify, as that
            // would alter whitespace and invalidate the signature.
            return xmlDoc.OuterXml;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign MX document");
            throw;
        }
    }

    private XmlElement BuildKeyInfoElement(XmlDocument xmlDoc, string keyInfoId)
    {
        var keyInfo = xmlDoc.CreateElement("ds", "KeyInfo", DsNs);
        keyInfo.SetAttribute("Id", keyInfoId);

        var x509Data = xmlDoc.CreateElement("ds", "X509Data", DsNs);
        var x509IssuerSerial = xmlDoc.CreateElement("ds", "X509IssuerSerial", DsNs);

        var issuerName = xmlDoc.CreateElement("ds", "X509IssuerName", DsNs);
        issuerName.InnerText = _certificate!.Issuer;

        var serialNumber = xmlDoc.CreateElement("ds", "X509SerialNumber", DsNs);
        serialNumber.InnerText = _certificate.SerialNumber is not null
            ? new System.Numerics.BigInteger(
                Convert.FromHexString(_certificate.SerialNumber), isUnsigned: true, isBigEndian: true).ToString()
            : "0";

        x509IssuerSerial.AppendChild(issuerName);
        x509IssuerSerial.AppendChild(serialNumber);
        x509Data.AppendChild(x509IssuerSerial);
        keyInfo.AppendChild(x509Data);

        return keyInfo;
    }

    private static XmlElement BuildSignedPropertiesElement(XmlDocument xmlDoc, string signedPropsId)
    {
        var signedProps = xmlDoc.CreateElement("xades", "SignedProperties", XadesNs);
        signedProps.SetAttribute("Id", signedPropsId);

        var signedSigProps = xmlDoc.CreateElement("xades", "SignedSignatureProperties", XadesNs);

        var signingTime = xmlDoc.CreateElement("xades", "SigningTime", XadesNs);
        signingTime.InnerText = DateTimeOffset.Now.ToString("yyyy-MM-dd'T'HH:mm:sszzz");

        signedSigProps.AppendChild(signingTime);
        signedProps.AppendChild(signedSigProps);

        return signedProps;
    }

    private static XmlElement BuildSignedInfoElement(
        XmlDocument xmlDoc,
        string keyInfoId, string keyInfoDigest,
        string signedPropsId, string signedPropsDigest,
        string documentDigest)
    {
        var signedInfo = xmlDoc.CreateElement("ds", "SignedInfo", DsNs);

        // CanonicalizationMethod
        var c14nMethod = xmlDoc.CreateElement("ds", "CanonicalizationMethod", DsNs);
        c14nMethod.SetAttribute("Algorithm", ExcC14NAlgorithm);
        signedInfo.AppendChild(c14nMethod);

        // SignatureMethod
        var sigMethod = xmlDoc.CreateElement("ds", "SignatureMethod", DsNs);
        sigMethod.SetAttribute("Algorithm", RsaSha256Algorithm);
        signedInfo.AppendChild(sigMethod);

        // Référence 1 : KeyInfo
        signedInfo.AppendChild(BuildReferenceElement(
            xmlDoc, "#" + keyInfoId, null, keyInfoDigest));

        // Référence 2 : SignedProperties
        signedInfo.AppendChild(BuildReferenceElement(
            xmlDoc, "#" + signedPropsId, "http://uri.etsi.org/01903/v1.3.2#SignedProperties", signedPropsDigest));

        // Référence 3 : Document (sans URI)
        signedInfo.AppendChild(BuildReferenceElement(
            xmlDoc, null, null, documentDigest));

        return signedInfo;
    }

    private static XmlElement BuildReferenceElement(
        XmlDocument xmlDoc, string? uri, string? type, string digestValue)
    {
        var reference = xmlDoc.CreateElement("ds", "Reference", DsNs);
        if (uri is not null)
            reference.SetAttribute("URI", uri);
        if (type is not null)
            reference.SetAttribute("Type", type);

        var transforms = xmlDoc.CreateElement("ds", "Transforms", DsNs);
        var transform = xmlDoc.CreateElement("ds", "Transform", DsNs);
        transform.SetAttribute("Algorithm", ExcC14NAlgorithm);
        transforms.AppendChild(transform);
        reference.AppendChild(transforms);

        var digestMethod = xmlDoc.CreateElement("ds", "DigestMethod", DsNs);
        digestMethod.SetAttribute("Algorithm", Sha256DigestAlgorithm);
        reference.AppendChild(digestMethod);

        var digestValueElem = xmlDoc.CreateElement("ds", "DigestValue", DsNs);
        digestValueElem.InnerText = digestValue;
        reference.AppendChild(digestValueElem);

        return reference;
    }

    private XmlElement BuildSignatureElement(
        XmlDocument xmlDoc, string signatureId,
        XmlElement signedInfoElement, string signatureValue,
        XmlElement keyInfoElement, XmlElement signedPropsElement,
        string signedPropsId, string sigId)
    {
        var signature = xmlDoc.CreateElement("ds", "Signature", DsNs);
        signature.SetAttribute("Id", signatureId);

        signature.AppendChild(signedInfoElement);

        var sigValueElem = xmlDoc.CreateElement("ds", "SignatureValue", DsNs);
        sigValueElem.InnerText = signatureValue;
        signature.AppendChild(sigValueElem);

        signature.AppendChild(keyInfoElement);

        // ds:Object contenant QualifyingProperties
        var objectElem = xmlDoc.CreateElement("ds", "Object", DsNs);

        var qualifyingProps = xmlDoc.CreateElement("xades", "QualifyingProperties", XadesNs);
        qualifyingProps.SetAttribute("Target", "#" + sigId);
        qualifyingProps.AppendChild(signedPropsElement);

        objectElem.AppendChild(qualifyingProps);
        signature.AppendChild(objectElem);

        return signature;
    }

    private static byte[] CanonicalizeElementToBytes(XmlElement element)
    {
        var tmpDoc = new XmlDocument { PreserveWhitespace = true };
        tmpDoc.AppendChild(tmpDoc.ImportNode(element, true));

        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(tmpDoc);
        using var stream = (MemoryStream)transform.GetOutput(typeof(System.IO.Stream));
        return stream.ToArray();
    }

    private static string CanonicalizeElement(XmlElement element)
    {
        var bytes = CanonicalizeElementToBytes(element);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }

    private static string ComputeSha256Digest(string canonicalXml)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(canonicalXml);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    private string ComputeRsaSha256Signature(string canonicalSignedInfo)
    {
        var data = System.Text.Encoding.UTF8.GetBytes(canonicalSignedInfo);
        using var rsa = _certificate!.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("RSA private key not available");
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    public bool VerifySignature(string signedDocument)
    {
        return VerifySignature(signedDocument, _certificate);
    }

    public bool VerifySignature(string signedDocument, X509Certificate2? certificate)
    {
        if (certificate == null)
        {
            _logger.LogWarning("No certificate provided for signature verification");
            return false;
        }

        try
        {
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(signedDocument);

            var signatureElement = xmlDoc.SelectSingleNode("//*[local-name()='Signature']") as XmlElement;
            if (signatureElement == null)
            {
                _logger.LogWarning("Signature element not found");
                return false;
            }

            // Vérifier la présence de SignedProperties (XAdES)
            var nsMgr = new XmlNamespaceManager(xmlDoc.NameTable);
            nsMgr.AddNamespace("xades", XadesNs);
            var signedPropsNode = signatureElement.SelectSingleNode(".//xades:SignedProperties", nsMgr);
            if (signedPropsNode == null)
            {
                _logger.LogWarning("SignedProperties element not found in signature");
                return false;
            }

            // Manually verify each reference and the signature value,
            // because SignedXml.CheckSignature cannot resolve the no-URI Reference
            // that points to the <Document> element.
            var signedXml = new XadesSignedXml(xmlDoc);
            signedXml.LoadXml(signatureElement);

            // 1. Verify each Reference digest
            foreach (Reference reference in signedXml.SignedInfo.References)
            {
                if (string.IsNullOrEmpty(reference.Uri))
                {
                    // No-URI reference → resolve to the <Document> element
                    var documentElement = xmlDoc.SelectSingleNode("//*[local-name()='Document']") as XmlElement;
                    if (documentElement == null)
                    {
                        _logger.LogWarning("Document element not found for no-URI reference");
                        return false;
                    }

                    var canonicalBytes = CanonicalizeElementToBytes(documentElement);
                    var computedHash = SHA256.HashData(canonicalBytes);
                    var expectedHash = Convert.FromBase64String(reference.DigestValue is not null
                        ? Convert.ToBase64String(reference.DigestValue) : "");

                    // DigestValue is already a byte[], compare directly
                    if (!CryptographicOperations.FixedTimeEquals(computedHash, reference.DigestValue))
                    {
                        _logger.LogWarning("Document reference digest mismatch");
                        return false;
                    }
                }
                else if (reference.Uri.StartsWith('#'))
                {
                    var id = reference.Uri[1..];
                    var referencedElement = signedXml.GetIdElement(xmlDoc, id);
                    if (referencedElement == null)
                    {
                        _logger.LogWarning("Referenced element not found for URI: {Uri}", reference.Uri);
                        return false;
                    }

                    var canonicalBytes = CanonicalizeElementToBytes(referencedElement);
                    var computedHash = SHA256.HashData(canonicalBytes);

                    if (!CryptographicOperations.FixedTimeEquals(computedHash, reference.DigestValue))
                    {
                        _logger.LogWarning("Reference digest mismatch for URI: {Uri}", reference.Uri);
                        return false;
                    }
                }
            }

            // 2. Verify the SignatureValue over the canonicalized SignedInfo
            var signedInfoElement = signatureElement.SelectSingleNode("*[local-name()='SignedInfo']") as XmlElement;
            if (signedInfoElement == null)
            {
                _logger.LogWarning("SignedInfo element not found");
                return false;
            }

            var signedInfoCanonical = CanonicalizeElementToBytes(signedInfoElement);
            var signatureValueText = signedXml.SignatureValue;

            using var rsa = certificate.GetRSAPublicKey();
            if (rsa == null)
            {
                _logger.LogWarning("RSA public key not available from certificate");
                return false;
            }

            var isValid = rsa.VerifyData(signedInfoCanonical, signatureValueText,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            _logger.LogInformation("Signature verification: {IsValid}", isValid);
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signature verification failed");
            return false;
        }
    }

    /// <summary>
    /// Sous-classe de SignedXml qui résout les éléments par attribut Id
    /// pour supporter les références XAdES (SignedProperties, KeyInfo).
    /// </summary>
    private sealed class XadesSignedXml(XmlDocument document) : SignedXml(document)
    {
        public override XmlElement? GetIdElement(XmlDocument? doc, string id)
        {
            var element = base.GetIdElement(doc, id);
            if (element != null)
                return element;

            if (doc?.DocumentElement == null)
                return null;

            return FindElementById(doc.DocumentElement, id);
        }

        private static XmlElement? FindElementById(XmlElement root, string id)
        {
            if (root.GetAttribute("Id") == id)
                return root;

            foreach (XmlNode child in root.ChildNodes)
            {
                if (child is XmlElement childElement)
                {
                    var found = FindElementById(childElement, id);
                    if (found != null)
                        return found;
                }
            }

            return null;
        }
    }

    private string MinifyXml(string xml)
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xml);

        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings
        {
            Indent = true,
            OmitXmlDeclaration = false,
            NewLineHandling = NewLineHandling.Entitize
        });

        xmlDoc.Save(xmlWriter);
        return stringWriter.ToString();
    }

}