package se.highex.examples.signatures.mx.service;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import se.highex.examples.signatures.mx.util.CryptoRuntimeException;
import se.highex.examples.signatures.mx.util.Utils;

@Service
public class CryptoService implements ApplicationListener<ApplicationReadyEvent> {

	private static final Logger logger = LoggerFactory.getLogger(CryptoService.class);

	private final Environment environment;

	private final SignerService signerService;

	private final VerifierService verifierService;

	public CryptoService(Environment environment, SignerService signerService, VerifierService verifierService) {
		this.environment = environment;
		this.signerService = signerService;
		this.verifierService = verifierService;
	}

	@Override
	public void onApplicationEvent(ApplicationReadyEvent event) {
		try {
			var action = getProperty("se.highex.example.action", true);
			var keystoreFile = getProperty("se.highex.example.keystoreFile", false);
			if ("sign".equalsIgnoreCase(action)) {
				if (keystoreFile == null) {
					throw new CryptoRuntimeException(
							"Property \"se.highex.example.keystoreFile\" is mandatory for sign");
				}
				var ks = loadKeystore(keystoreFile);
				sign(ks);
			}
			else if ("verify".equalsIgnoreCase(action)) {
				if (keystoreFile == null) {
					var certFile = getProperty("se.highex.example.certFile", true);
					var cf = CertificateFactory.getInstance("X.509");
					try (var is = new FileInputStream(certFile)) {
						var certificate = (X509Certificate) cf.generateCertificate(is);
						verify(certificate);
					}
				}
				else {
					var keyAlias = getProperty("se.highex.example.keyAlias", true);
					var ks = loadKeystore(keystoreFile);
					var certificate = (X509Certificate) ks.getCertificate(keyAlias);
					verify(certificate);
				}
			}
			else {
				throw new CryptoRuntimeException(
						"Property \"se.highex.example.action\" must be \"sign\" or \"verify\"");
			}
		}
		catch (CryptoRuntimeException cre) {
			throw cre;
		}
		catch (Exception ex) {
			throw new CryptoRuntimeException(ex);
		}
	}

	public void sign(KeyStore ks) throws GeneralSecurityException, TransformerException, IOException, SAXException,
			MarshalException, XMLSignatureException, ParserConfigurationException {
		var keyAlias = getProperty("se.highex.example.keyAlias", true);
		var keyPass = getProperty("se.highex.example.keyPass", false);
		if (keyPass == null) {
			keyPass = getProperty("se.highex.example.keystorePass", true);
		}
		var documentPath = getProperty("se.highex.example.documentToSign", true);

		var certificate = (X509Certificate) ks.getCertificate(keyAlias);
		var privateKey = (PrivateKey) ks.getKey(keyAlias, keyPass.toCharArray());
		var builder = Utils.createDocumentBuilder();
		var transformer = Utils.createTransformer();
		var doc = builder.parse(new InputSource(new FileReader(documentPath)));

		var signedDoc = this.signerService.sign(doc, privateKey, certificate);

		String signedDocumentPath;
		if (documentPath.endsWith(".xml")) {
			signedDocumentPath = documentPath.substring(0, documentPath.lastIndexOf(".xml")) + "-signed.xml";
		}
		else {
			signedDocumentPath = documentPath + "-signed";
		}
		try (var fw = new FileWriter(signedDocumentPath)) {
			transformer.transform(new DOMSource(signedDoc), new StreamResult(fw));
			logger.info("File \"{}\" was successfully signed, signed file: \"{}\"", documentPath, signedDocumentPath);
		}
	}

	public void verify(X509Certificate certificate)
			throws IOException, SAXException, XPathException, ParserConfigurationException {
		var signedDocumentPath = getProperty("se.highex.example.documentToVerify", true);
		var builder = Utils.createDocumentBuilder();
		try (var fr = new FileReader(signedDocumentPath)) {
			var signedDoc = builder.parse(new InputSource(fr));
			this.verifierService.verify(signedDoc, certificate);
			logger.info("File \"{}\" was successfully verified", signedDocumentPath);
		}
	}

	private KeyStore loadKeystore(String keystoreFile) throws GeneralSecurityException, IOException {
		var keystorePass = getProperty("se.highex.example.keystorePass", true);
		var keystoreType = getProperty("se.highex.example.keystoreType", false);
		if (keystoreType == null || keystoreType.isEmpty()) {
			keystoreType = "JKS";
		}
		var ks = KeyStore.getInstance(keystoreType);
		ks.load(Files.newInputStream(Paths.get(keystoreFile)), keystorePass.toCharArray());
		return ks;
	}

	private String getProperty(String name, boolean required) {
		var value = this.environment.getProperty(name);
		if (required && value == null) {
			throw new CryptoRuntimeException("Property \"" + name + "\" was not found");
		}
		return value;
	}

}
