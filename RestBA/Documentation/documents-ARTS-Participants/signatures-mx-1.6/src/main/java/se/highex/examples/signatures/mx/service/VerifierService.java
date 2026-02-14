package se.highex.examples.signatures.mx.service;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import se.highex.examples.signatures.mx.util.CryptoRuntimeException;
import se.highex.examples.signatures.mx.util.NoUriDereferencer;
import se.highex.examples.signatures.mx.util.Utils;

@Service
public class VerifierService {

	private static final Logger logger = LoggerFactory.getLogger(VerifierService.class);

	/**
	 * Verifies document with specified certificate.
	 * @param document document (DataPDU or Xchg)
	 * @param signerCertificate certificate
	 */
	public void verify(Document document, X509Certificate signerCertificate) throws XPathException {
		var xpath = XPathFactory.newInstance().newXPath();
		var xpathExpression = "//*[local-name()='Signature']";
		var nodes = (NodeList) xpath.evaluate(xpathExpression, document.getDocumentElement(), XPathConstants.NODESET);
		if (nodes == null || nodes.getLength() == 0) {
			throw new CryptoRuntimeException("Signature is missing in the document");
		}
		int nodesCount = nodes.getLength();

		var dereferencers = createNoUriDereferencers(document, nodesCount);
		if (dereferencers.isEmpty() || dereferencers.size() != nodesCount) {
			throw new CryptoRuntimeException("Dereferences empty or not correlate with signatures count");
		}
		logger.trace("Found {} signatures in the document", nodesCount);

		var fac = Utils.createXMLSignatureFactory();

		for (int i = 0; i < nodes.getLength(); i++) {
			var nodeSignature = (Element) nodes.item(i);

			try {

				var keySelector = new KeySelector() {
					@Override
					public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
							XMLCryptoContext context) {
						return signerCertificate::getPublicKey;
					}
				};

				var valContext = new DOMValidateContext(keySelector, nodeSignature);
				valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
				valContext.setURIDereferencer(dereferencers.get(i));

				// Java 1.7.0_25+ complicates validation of
				// ds:Object/QualifyingProperties/SignedProperties
				// See details at https://bugs.openjdk.java.net/browse/JDK-8019379
				//
				// One of the solutions is to register the Id attribute using the
				// DOMValidateContext.setIdAttributeNS
				// method before validating the signature
				var nl = nodeSignature.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
				if (nl.getLength() == 0) {
					throw new CryptoRuntimeException("SignerProperties is missing in signature");
				}
				var elemSignedProps = (Element) nl.item(0);
				valContext.setIdAttributeNS(elemSignedProps, null, "Id");
				if (logger.isDebugEnabled()) {
					valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
				}

				var signature = fac.unmarshalXMLSignature(valContext);
				if (logger.isDebugEnabled()) {
					// pre validate references to see them even for success validations
					for (var ref : signature.getSignedInfo().getReferences()) {
						ref.validate(valContext);
					}
				}
				var coreValidity = signature.validate(valContext);
				if (logger.isDebugEnabled()) {
					var it = signature.getSignedInfo().getReferences().iterator();
					for (int j = 0; it.hasNext(); j++) {
						var ref = it.next();
						logger.debug("ref #{} URI: [{}]", j, ref.getURI());
						try (var in = ref.getDigestInputStream()) {
							byte[] data = Utils.toByteArray(in);
							logger.debug("Pre-digested data ({} bytes):\n{}", data.length, Utils.buildHexDump(data));
						}
					}
					try (var in = signature.getSignedInfo().getCanonicalizedData()) {
						byte[] data = Utils.toByteArray(in);
						logger.debug("Data to verify ({} bytes):\n{}", data.length, Utils.buildHexDump(data));
					}
				}
				if (coreValidity) {
					var stl = elemSignedProps.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#",
							"SigningTime");
					if (stl.getLength() == 0) {
						throw new CryptoRuntimeException("SigningTime is missing in signature");
					}
					var signingTimeElem = (Element) stl.item(0);
					var signingTime = Date.from(ZonedDateTime.parse(signingTimeElem.getTextContent()).toInstant());
					if (signingTime.before(signerCertificate.getNotBefore())
							|| signingTime.after(signerCertificate.getNotAfter())) {
						throw new CryptoRuntimeException("SigningTime is outside of certificate validity ");
					}
				}
				else {
					// signature verification failed
					logger.error("Signature #{} failed core validation", (i + 1));
					var sv = signature.getSignatureValue().validate(valContext);
					logger.info("Signature #{} validation status: {}", (i + 1), sv);
					// check the validation status of each Reference
					var it = signature.getSignedInfo().getReferences().iterator();
					for (int j = 0; it.hasNext(); j++) {
						var ref = it.next();
						var refValid = ref.validate(valContext);
						logger.info("ref[{}] validity status: {}, ref URI: [{}]", j, refValid, ref.getURI());
					}
				}
			}
			catch (DOMException | CryptoRuntimeException | MarshalException | XMLSignatureException | IOException ex) {
				logger.error(ex.getMessage(), ex);
				throw new CryptoRuntimeException(ex);
			}
		}
	}

	// Creates a custom URIDereferencers to process References without URI.
	private List<URIDereferencer> createNoUriDereferencers(Document doc, int signaturesCount)
			throws CryptoRuntimeException {
		var result = new ArrayList<URIDereferencer>(signaturesCount);
		var docNodes = doc.getElementsByTagName("Document");
		var isXchg = Utils.isXchg(doc);
		if (isXchg) {
			int expectedDocCount = signaturesCount - 1;
			if (expectedDocCount == 0) {
				logger.debug("Only Xchg signature found, {} documents are not signed", docNodes.getLength());
			}
			else if (expectedDocCount < docNodes.getLength()) {
				logger.warn("Some documents inside Xchg are not signed? document signatures found: {}, documents: {}",
						expectedDocCount, docNodes.getLength());
			}
			else if (expectedDocCount != docNodes.getLength()) {
				throw new CryptoRuntimeException(
						"Wrong documents count, expected: " + expectedDocCount + ", actual: " + docNodes.getLength());
			}
			result.add(new NoUriDereferencer(doc.getDocumentElement()));
			for (int i = 0; i < docNodes.getLength(); i++) {
				var docNode = docNodes.item(i);
				var parent = (Element) docNode.getParentNode();
				if (parent.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength() == 1) {
					result.add(new NoUriDereferencer(docNode));
				}
			}
		}
		else {
			var dereferencer = new NoUriDereferencer(docNodes.item(0));
			for (int i = 0; i < signaturesCount; i++) {
				result.add(dereferencer);
			}
		}
		return result;
	}

}
