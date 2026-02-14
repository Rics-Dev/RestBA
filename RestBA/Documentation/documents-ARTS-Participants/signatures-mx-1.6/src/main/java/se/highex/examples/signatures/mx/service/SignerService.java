package se.highex.examples.signatures.mx.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import se.highex.examples.signatures.mx.util.CryptoRuntimeException;
import se.highex.examples.signatures.mx.util.NoUriDereferencer;
import se.highex.examples.signatures.mx.util.Utils;

@Service
public class SignerService {

	private static final Logger logger = LoggerFactory.getLogger(SignerService.class);

	/**
	 * The RSAwithSHA256 signature method algorithm URI.
	 */
	private static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

	/**
	 * The XAdES namespace URI.
	 */
	private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";

	/**
	 * Signs document with provided private key and certificate.
	 * @param doc document (DataPDU or Xchg)
	 * @param privateKey private key
	 * @param signerCertificate certificate
	 * @return signed document (DataPDU)
	 */
	public Document sign(Document doc, PrivateKey privateKey, X509Certificate signerCertificate)
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, MarshalException,
			XMLSignatureException {
		var fac = Utils.createXMLSignatureFactory();
		var digestMethod = fac.newDigestMethod(DigestMethod.SHA256, null);
		var canonicalizationMethod = fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
				(XMLStructure) null);
		var signatureMethod = fac.newSignatureMethod(RSA_SHA256, null);

		// 1. Prepare KeyInfo
		var kif = fac.getKeyInfoFactory();
		var x509is = kif.newX509IssuerSerial(signerCertificate.getIssuerX500Principal().toString(),
				signerCertificate.getSerialNumber());
		var x509data = kif.newX509Data(Collections.singletonList(x509is));
		var keyInfoId = "_" + UUID.randomUUID();
		var ki = kif.newKeyInfo(Collections.singletonList(x509data), keyInfoId);

		// 2. Prepare references
		var refs = new ArrayList<Reference>();
		var signedPropsId = "_" + UUID.randomUUID() + "-signedprops";
		var ref1 = fac.newReference("#" + keyInfoId, digestMethod, Collections.singletonList(canonicalizationMethod),
				null, null);
		refs.add(ref1);
		var ref2 = fac.newReference("#" + signedPropsId, digestMethod,
				Collections.singletonList(canonicalizationMethod), "http://uri.etsi.org/01903/v1.3.2#SignedProperties",
				null);
		refs.add(ref2);

		var ref3Transforms = createNoUriTransforms(doc, fac);
		var ref3 = fac.newReference(null, fac.newDigestMethod(DigestMethod.SHA256, null), ref3Transforms, null, null);
		refs.add(ref3);
		var si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, refs);

		// 3. Find or create element Sgntr that will contain the <ds:Signature>
		var sgntr = findOrCreateSignatureNode(doc);

		var dsc = new DOMSignContext(privateKey, sgntr);
		if (logger.isDebugEnabled()) {
			dsc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
		}
		dsc.putNamespacePrefix(XMLSignature.XMLNS, "ds");

		// 4. Set up <ds:Object> with <QualifiyingProperties> inside that includes
		// SigningTime
		var signatureId = "_" + UUID.randomUUID();
		var qpElement = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
		qpElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", XADES_NS);
		qpElement.setAttribute("Target", "#" + signatureId);

		var spElement = doc.createElementNS(XADES_NS, "xades:SignedProperties");
		spElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", XADES_NS);
		spElement.setAttributeNS(null, "Id", signedPropsId);
		dsc.setIdAttributeNS(spElement, null, "Id");
		spElement.setIdAttributeNS(null, "Id", true);
		qpElement.appendChild(spElement);

		var sspElement = doc.createElementNS(XADES_NS, "xades:SignedSignatureProperties");
		spElement.appendChild(sspElement);

		var df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
		var signingTime = df.format(new Date());

		var stElement = doc.createElementNS(XADES_NS, "xades:SigningTime");
		stElement.appendChild(doc.createTextNode(signingTime));
		sspElement.appendChild(stElement);

		var qualifPropStruct = new DOMStructure(qpElement);

		var xmlObj = new ArrayList<DOMStructure>();
		xmlObj.add(qualifPropStruct);
		var object = fac.newXMLObject(xmlObj, null, null, null);

		var objects = Collections.singletonList(object);

		// 5. Set up custom URIDereferencer to process Reference without URI.
		// This Reference points to element <Document> or <Xchg>
		dsc.setURIDereferencer(createNoUriDereferencer(doc));

		// 6. sign it!
		var signature = fac.newXMLSignature(si, ki, objects, signatureId, null);
		signature.sign(dsc);

		if (logger.isDebugEnabled()) {
			int i = 0;
			for (var ref : refs) {
				var digValStr = Utils.digestToString(ref.getDigestValue());
				i++;
				logger.debug("ref #{} URI: [{}], digest: {}", i, ref.getURI(), digValStr);
				try (var in = ref.getDigestInputStream()) {
					byte[] data = Utils.toByteArray(in);
					logger.debug("Pre-digested data ({} bytes):\n{}", data.length, Utils.buildHexDump(data));
				}
			}
			try (var in = signature.getSignedInfo().getCanonicalizedData()) {
				byte[] data = Utils.toByteArray(in);
				logger.debug("Data to be signed ({} bytes):\n{}", data.length, Utils.buildHexDump(data));
			}
		}

		return doc;
	}

	private URIDereferencer createNoUriDereferencer(Document doc) throws CryptoRuntimeException {
		var isXchg = Utils.isXchg(doc);
		if (isXchg) {
			return new NoUriDereferencer(doc.getDocumentElement());
		}
		// This Reference points to element <Document> of MX message
		var noUriNodes = doc.getElementsByTagName("Document");
		if (noUriNodes.getLength() == 0) {
			throw new CryptoRuntimeException("mandatory element Document is missing in the document to be signed");
		}
		var noUriNode = noUriNodes.item(0);
		return new NoUriDereferencer(noUriNode);
	}

	protected Node findOrCreateSignatureNode(Document doc) throws CryptoRuntimeException {
		var isXchg = Utils.isXchg(doc);
		var nextNodeName = isXchg ? "TtlNbOfDocs" : "Rltd";
		var sgntrParent = findOrCreateSignatureParent(doc, isXchg);
		var sgntrParentChildList = sgntrParent.getChildNodes();
		Node sgntr = null;
		Node nextNode = null;
		for (int i = 0; i < sgntrParentChildList.getLength(); i++) {
			var childNode = sgntrParentChildList.item(i);
			if (childNode.getNodeType() == Node.ELEMENT_NODE) {
				if (Objects.equals(childNode.getLocalName(), "Sgntr")) {
					sgntr = childNode;
				}
				else if (Objects.equals(childNode.getLocalName(), nextNodeName)) {
					nextNode = childNode;
				}
			}
		}
		if (sgntr == null) {
			if (nextNode == null) {
				sgntr = sgntrParent.appendChild(doc.createElementNS(sgntrParent.getNamespaceURI(), "Sgntr"));
			}
			else {
				sgntr = sgntrParent.insertBefore(doc.createElementNS(sgntrParent.getNamespaceURI(), "Sgntr"), nextNode);
			}
		}
		return sgntr;
	}

	private Node findOrCreateSignatureParent(Document doc, boolean isXchg) throws CryptoRuntimeException {
		Node sgntrParent = null;
		if (isXchg) {
			var sgntrParentList = doc.getElementsByTagName("ApplSpcfcs");
			if (sgntrParentList.getLength() != 0) {
				sgntrParent = sgntrParentList.item(0);
			}
			if (sgntrParent == null) {
				Node pyldDesc = null;
				var pyldDescList = doc.getElementsByTagName("PyldDesc");
				if (pyldDescList.getLength() > 0) {
					pyldDesc = pyldDescList.item(0);
				}
				if (pyldDesc == null) {
					logger.error("mandatory element PyldDesc is missing in the document to be signed");
					throw new CryptoRuntimeException(
							"mandatory element PyldDesc is missing in the document to be signed");
				}
				Node pyldTp = null;
				var pyldDescChildList = pyldDesc.getChildNodes();
				for (int i = 0; i < pyldDescChildList.getLength(); i++) {
					var childNode = pyldDescChildList.item(i);
					if (childNode.getNodeType() == Node.ELEMENT_NODE) {
						if (Objects.equals(childNode.getLocalName(), "PyldTp")) {
							pyldTp = childNode;
						}
					}
				}
				sgntrParent = pyldDesc.insertBefore(doc.createElementNS(pyldDesc.getNamespaceURI(), "ApplSpcfcs"),
						pyldTp);
			}
		}
		else {
			var parentNodeName = "AppHdr";
			var sgntrParentList = doc.getElementsByTagName(parentNodeName);
			if (sgntrParentList.getLength() != 0) {
				sgntrParent = sgntrParentList.item(0);
			}
			if (sgntrParent == null) {
				logger.error("mandatory element {} is missing in the document to be signed", parentNodeName);
				throw new CryptoRuntimeException(
						"mandatory element " + parentNodeName + " is missing in the document to be signed");
			}
		}
		return sgntrParent;
	}

	private List<Transform> createNoUriTransforms(Document doc, XMLSignatureFactory fac)
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		var isXchg = Utils.isXchg(doc);
		var transforms = new ArrayList<Transform>();
		if (isXchg) {
			logger.trace("Adding {} transform", Transform.ENVELOPED);
			transforms.add(fac.newTransform(Transform.ENVELOPED, (XMLStructure) null));
		}
		transforms.add(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null));
		return transforms;
	}

}
