package se.highex.examples.signatures.mx.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public final class TestUtils {

	public static KeyPair createKeyPair() throws GeneralSecurityException {
		var kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(2048, new SecureRandom());
		return kpg.generateKeyPair();
	}

	public static X509Certificate createCertificate(PublicKey publicKey)
			throws GeneralSecurityException, OperatorCreationException, IOException {
		var issuerKeyPair = createKeyPair();
		var issuerPrivateKey = issuerKeyPair.getPrivate();
		var issuerPublicKey = issuerKeyPair.getPublic();

		var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded()));

		var now = System.currentTimeMillis();
		var random = new SecureRandom();
		var randomSerial = random.nextInt(Integer.MAX_VALUE - 1) + 1;

		var v3CertGen = new X509v3CertificateBuilder(
				new X500Name(RFC4519Style.INSTANCE, "C=SE,O=CMA Small Systems AB,CN=Test CA"),
				new BigInteger(String.valueOf(randomSerial)), new Date(now), new Date(now + 1000L * 60 * 60 * 24 * 100),
				new X500Name(RFC4519Style.INSTANCE, "C=SE,O=CMA Small Systems AB,CN=Test"), subjectPublicKeyInfo);

		var builder = new JcaContentSignerBuilder("SHA256WITHRSA");
		var signer = builder.build(issuerPrivateKey);

		var x509ExtensionUtils = new BcX509ExtensionUtils();
		v3CertGen.addExtension(Extension.subjectKeyIdentifier, false,
				x509ExtensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo
					.getInstance(new ASN1InputStream(new ByteArrayInputStream(publicKey.getEncoded())).readObject())));

		v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
				x509ExtensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(
						new ASN1InputStream(new ByteArrayInputStream(issuerPublicKey.getEncoded())).readObject())));

		v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

		var certBytes = v3CertGen.build(signer).getEncoded();
		var certificateFactory = CertificateFactory.getInstance("X.509");
		var cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

		cert.checkValidity(new Date(now));
		cert.verify(issuerPublicKey);

		return cert;
	}

	public static Document loadDocument(String path) throws IOException, SAXException, ParserConfigurationException {
		try (var in = TestUtils.class.getResourceAsStream(path)) {
			var builder = Utils.createDocumentBuilder();
			return builder.parse(in);
		}
	}

	public static String saveDocument(Document doc) throws TransformerException {
		var transformer = Utils.createTransformer();
		var writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		return writer.toString();
	}

	private TestUtils() {
	}

}
