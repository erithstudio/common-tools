package com.erith.commontools.security.xmlsignature;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.ParserConfigurationException;

import com.erith.commontools.security.xmlsignature.algorithm.pgp.PgpKeyProvider;
import com.erith.commontools.security.xmlsignature.algorithm.Pkcs12KeyProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XmlValidator extends DomValidationOperator {

	private PrivateKeyProvider keyProvider;

    public XmlValidator(int type, PrivateKeyData keyData, String publicKeyFilepath) throws Exception {
    	if(type == SecurityConstants.TYPE_PKCS12) {
    		keyProvider = new Pkcs12KeyProvider(factory, keyData);
    	} else if(type == SecurityConstants.TYPE_PKCS12_PGP) {
    		keyProvider = new PgpKeyProvider(factory, keyData, publicKeyFilepath);
    	} else {
    		throw new Exception("No Encryption Type");
    	}
    }

    /**
     * @throws SignatureNotFound if there is not element "Signature" on the top level of the document.
     */
    public boolean isValid(String pathToDocument) throws SignatureNotFound, MarshalException, XMLSignatureException, CertificateException, IOException, SAXException, ParserConfigurationException {
        Document document = loadDocument(pathToDocument);
        return validateDocumentWithKey(document, keyProvider.loadPublicKey());
    }

    private boolean validateDocumentWithKey(Document document, PublicKey key) throws MarshalException, XMLSignatureException {
        Node item = findSignatureElement(document);
        DOMValidateContext validateContext = new DOMValidateContext(key, item);
        XMLSignature signature = factory.unmarshalXMLSignature(validateContext);
        return signature.validate(validateContext);
    }

    private Document loadDocument(String pathToDocument) throws SAXException, IOException, ParserConfigurationException {
        return new DocumentReader(pathToDocument).loadDocument();
    }

      private Node findSignatureElement(Document document) {
        NodeList nodeList = document.getElementsByTagNameNS(XMLNS, "Signature");
        if (nodeList.getLength() == 0) {
            throw new SignatureNotFound();
        }
        return nodeList.item(0);
    }
}