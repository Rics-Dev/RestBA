using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.Extensions.Options;
using RestBA.Options;

namespace RestBA.Services;

public class SignatureService
{
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
            var xmlDoc = new XmlDocument { PreserveWhitespace = false };
            xmlDoc.LoadXml(documentContent);

            // Extraire l'élément Document pour le signer
            var documentElement = xmlDoc.SelectSingleNode("//*[local-name()='Document']") as XmlElement;
            if (documentElement == null)
            {
                throw new Exception("Document element not found");
            }

            // Créer la signature XML
            var signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = _certificate.GetRSAPrivateKey();

            // Référence au Document (sans URI)
            var reference = new Reference("");
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            signedXml.AddReference(reference);

            // Créer KeyInfo avec X509IssuerSerial
            var keyInfo = new KeyInfo();
            var keyInfoId = "_" + Guid.NewGuid().ToString();
            
            var x509Data = new KeyInfoX509Data(_certificate);
            keyInfo.AddClause(x509Data);
            signedXml.KeyInfo = keyInfo;

            // Générer la signature
            signedXml.ComputeSignature();
            var signatureElement = signedXml.GetXml();

            // Insérer la signature dans AppHdr/Sgntr
            var appHdrElement = xmlDoc.SelectSingleNode("//*[local-name()='AppHdr']") as XmlElement;
            if (appHdrElement == null)
            {
                throw new Exception("AppHdr element not found");
            }

            var sgntrElement = xmlDoc.CreateElement("Sgntr", appHdrElement.NamespaceURI);
            sgntrElement.AppendChild(xmlDoc.ImportNode(signatureElement, true));
            appHdrElement.AppendChild(sgntrElement);

            // Retourner le XML minifié (sans espaces inutiles)
            return MinifyXml(xmlDoc.OuterXml);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign MX document");
            throw;
        }
    }

    public bool VerifySignature(string signedDocument)
    {
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

            var signedXml = new SignedXml(xmlDoc);
            signedXml.LoadXml(signatureElement);

            // Extraire le certificat de KeyInfo
            var keyInfo = signedXml.KeyInfo;
            X509Certificate2? cert = null;

            foreach (KeyInfoClause clause in keyInfo)
            {
                if (clause is KeyInfoX509Data x509Data)
                {
                    if (x509Data.Certificates?.Count > 0)
                    {
                        cert = x509Data.Certificates[0] as X509Certificate2;
                        break;
                    }
                }
            }

            if (cert == null)
            {
                _logger.LogWarning("Certificate not found in signature");
                return false;
            }

            // Vérifier la signature
            var isValid = signedXml.CheckSignature(cert, true);
            _logger.LogInformation("Signature verification: {IsValid}", isValid);
            
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signature verification failed");
            return false;
        }
    }

    private string MinifyXml(string xml)
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xml);
        
        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings
        {
            Indent = false,
            OmitXmlDeclaration = true,
            NewLineHandling = NewLineHandling.None
        });
        
        xmlDoc.Save(xmlWriter);
        return stringWriter.ToString();
    }
}