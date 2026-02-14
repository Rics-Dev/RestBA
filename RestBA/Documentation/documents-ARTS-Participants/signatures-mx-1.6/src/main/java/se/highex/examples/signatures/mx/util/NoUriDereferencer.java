package se.highex.examples.signatures.mx.util;

import javax.xml.crypto.Data;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.jcp.xml.dsig.internal.dom.DOMSubTreeData;
import org.w3c.dom.Node;

public class NoUriDereferencer implements URIDereferencer {

	private final Node noUriNode;

	public NoUriDereferencer(Node noUriNode) {
		if (noUriNode == null) {
			throw new IllegalArgumentException("No URI node is null");
		}
		this.noUriNode = noUriNode;
	}

	@Override
	public Data dereference(URIReference uriRef, XMLCryptoContext ctx) throws URIReferenceException {
		if (Utils.isBlank(uriRef.getURI())) {
			return new DOMSubTreeData(this.noUriNode, false);
		}
		var defaultDereferencer = XMLSignatureFactory.getInstance("DOM").getURIDereferencer();
		return defaultDereferencer.dereference(uriRef, ctx);
	}

}
