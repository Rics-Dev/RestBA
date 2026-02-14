package se.highex.examples.signatures.mx.service;

import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import se.highex.examples.signatures.mx.util.TestUtils;
import se.highex.examples.signatures.mx.util.Utils;

@ExtendWith(SpringExtension.class)
public class MxSignatureTests {

	private static final Logger logger = LoggerFactory.getLogger(MxSignatureTests.class);

	@Autowired
	private SignerService signerService;

	@Autowired
	private VerifierService verifierService;

	private PrivateKey privateKey;

	private X509Certificate certificate;

	@BeforeAll
	public static void beforeAll() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@BeforeEach
	public void beforeEach() throws Exception {
		var keyPair = TestUtils.createKeyPair();
		this.privateKey = keyPair.getPrivate();
		this.certificate = TestUtils.createCertificate(keyPair.getPublic());
	}

	@Test
	public void signVerifyDataPdu() throws Exception {
		signVerify("/pacs008.xml");
	}

	@Test
	public void signVerifyDataPduWithRltd() throws Exception {
		signVerify("/pacs008-rltd.xml");
	}

	@Test
	public void signVerifyXchg() throws Exception {
		signVerify("/xchg/head002.xml");
	}

	@Test
	public void signVerifyXchgWithBatches() throws Exception {
		var xchg = TestUtils.loadDocument("/xchg/head002-template.xml");
		var dataPdu1 = TestUtils.loadDocument("/xchg/pacs009-first.xml");
		var dataPdu2 = TestUtils.loadDocument("/xchg/pacs009-second.xml");

		var signedDataPdu1 = this.signerService.sign(dataPdu1, this.privateKey, this.certificate);
		var signedDataPdu2 = this.signerService.sign(dataPdu2, this.privateKey, this.certificate);
		var batchesNodeList = xchg.getElementsByTagName("Pyld");
		Assertions.assertEquals(2, batchesNodeList.getLength());
		var batchNode1 = batchesNodeList.item(0);
		Assertions.assertNotNull(batchNode1);
		batchNode1.appendChild(xchg.importNode(signedDataPdu1.getDocumentElement(), true));
		var batchNode2 = batchesNodeList.item(1);
		batchNode2.appendChild(xchg.importNode(signedDataPdu2.getDocumentElement(), true));
		var signedXchg = this.signerService.sign(xchg, this.privateKey, this.certificate);

		verify(signedXchg);
	}

	private void signVerify(String path) throws Exception {
		var doc = TestUtils.loadDocument(path);
		var signedDoc = this.signerService.sign(doc, this.privateKey, this.certificate);
		verify(signedDoc);
	}

	private void verify(Document signedDoc) throws Exception {
		var signedDocStr = TestUtils.saveDocument(signedDoc);
		logger.debug("Signed document: {}", signedDocStr);
		var builder = Utils.createDocumentBuilder();
		var docToVerify = builder.parse(new InputSource(new StringReader(signedDocStr)));
		this.verifierService.verify(docToVerify, this.certificate);
	}

	@TestConfiguration
	@Import({ SignerService.class, VerifierService.class })
	static class TestContextConfiguration {

	}

}
