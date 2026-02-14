package se.highex.examples.signatures.mx.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;

public final class Utils {

	private static final int BYTES_PER_LINE = 16;

	public static XMLSignatureFactory createXMLSignatureFactory() {
		if (Security.getProvider("ApacheXMLDSig") == null) {
			synchronized (Utils.class) {
				if (Security.getProvider("ApacheXMLDSig") == null) {
					Security.addProvider(new XMLDSigRI());
				}
			}
		}
		// force ignoreLineBreaks=true to avoid MIME base64 and CRLF in it.
		System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
		System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
		XMLSignatureFactory fac;
		try {
			fac = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
		}
		catch (NoSuchProviderException nspe) {
			try {
				fac = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
			}
			catch (NoSuchProviderException nspe2) {
				fac = XMLSignatureFactory.getInstance("DOM");
			}
		}
		return fac;
	}

	/**
	 * Create Transformer, protected from XML entity attacks. <a href=
	 * "https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet">https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet</a>
	 * @return transformer
	 */
	public static Transformer createTransformer() throws TransformerConfigurationException {
		var factory = TransformerFactory.newInstance();
		factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		return factory.newTransformer();
	}

	/**
	 * Create DocumentBuilder, protected from XML entity attacks. <a href=
	 * "https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet">https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet</a>
	 * @return document builder
	 */
	public static DocumentBuilder createDocumentBuilder() throws ParserConfigurationException {
		var factory = DocumentBuilderFactory.newInstance();
		String feature;
		// This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML
		// entity attacks are prevented
		feature = "http://apache.org/xml/features/disallow-doctype-decl";
		factory.setFeature(feature, true);

		// If you can't completely disable DTDs, then at least do the following:
		feature = "http://xml.org/sax/features/external-general-entities";
		factory.setFeature(feature, false);

		feature = "http://xml.org/sax/features/external-parameter-entities";
		factory.setFeature(feature, false);

		// Disable external DTDs as well
		feature = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
		factory.setFeature(feature, false);

		// and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and
		// Entity Attacks"
		factory.setXIncludeAware(false);
		factory.setExpandEntityReferences(false);

		factory.setNamespaceAware(true);
		return factory.newDocumentBuilder();
	}

	public static String buildHexDump(byte[] bytes) {
		if (bytes == null) {
			return "";
		}
		var buffer = new StringBuilder();
		int lineNumber = 0;
		int counter = 0;
		while (bytes.length > counter) {
			var sb1 = new StringBuilder();
			var sb2 = new StringBuilder(" ");
			buffer.append(String.format("%04X  ", lineNumber * BYTES_PER_LINE));
			for (int j = 0; j < BYTES_PER_LINE; j++) {

				if (counter < bytes.length) {
					byte value = bytes[counter];
					counter++;
					sb1.append(String.format("%02x ", 0xFF & value));
					if ((0xFF & value) > 0x1F) {
						sb2.append(((char) (0xFF & value)));
					}
					else {
						sb2.append(".");
					}
				}
				else {
					for (; j < BYTES_PER_LINE; j++) {
						sb1.append("   ");
					}
				}
			}
			buffer.append(sb1);
			buffer.append(sb2);
			buffer.append(String.format("%n"));
			lineNumber++;
		}
		return buffer.toString();
	}

	public static byte[] toByteArray(InputStream in) throws IOException {
		var buffer = new ByteArrayOutputStream();
		int nRead;
		byte[] chunk = new byte[4096];
		while ((nRead = in.read(chunk, 0, chunk.length)) != -1) {
			buffer.write(chunk, 0, nRead);
		}
		buffer.flush();
		return buffer.toByteArray();
	}

	public static String digestToString(byte[] digest) {
		var sb = new StringBuilder();
		for (byte b : digest) {
			var hex = Integer.toHexString(0xFF & b);
			if (hex.length() == 1) {
				sb.append('0');
			}
			sb.append(hex);
		}
		return sb.toString();
	}

	public static boolean isXchg(Document doc) {
		return "Xchg".equalsIgnoreCase(doc.getDocumentElement().getLocalName());
	}

	/**
	 *
	 * Checks if a CharSequence is empty (""), null or whitespace only.
	 *
	 * <p>
	 * Whitespace is defined by {@link Character#isWhitespace(char)}.
	 * </p>
	 *
	 * <pre>
	 * StringUtils.isBlank(null)      = true
	 * StringUtils.isBlank("")        = true
	 * StringUtils.isBlank(" ")       = true
	 * StringUtils.isBlank("bob")     = false
	 * StringUtils.isBlank("  bob  ") = false
	 * </pre>
	 * @param cs the CharSequence to check, may be null
	 * @return {@code true} if the CharSequence is null, empty or whitespace only
	 */
	public static boolean isBlank(final CharSequence cs) {
		var strLen = (cs != null) ? cs.length() : 0;
		if (strLen == 0) {
			return true;
		}
		for (int i = 0; i < strLen; i++) {
			if (!Character.isWhitespace(cs.charAt(i))) {
				return false;
			}
		}
		return true;
	}

	private Utils() {
	}

}
