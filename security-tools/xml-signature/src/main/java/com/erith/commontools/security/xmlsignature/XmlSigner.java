package com.erith.commontools.security.xmlsignature;

import static java.util.Collections.singletonList;
import static javax.xml.crypto.dsig.CanonicalizationMethod.INCLUSIVE;
import static javax.xml.crypto.dsig.SignatureMethod.RSA_SHA1;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import com.erith.commontools.security.xmlsignature.algorithm.pgp.PgpKeyProvider;
import com.erith.commontools.security.xmlsignature.algorithm.Pkcs12KeyProvider;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class XmlSigner extends DomValidationOperator {

    private static final String Entire_Document = "";
    private final PrivateKeyProvider provider;

    public XmlSigner(int type, PrivateKeyData keyData, String publicKeyFilepath) throws Exception {
    	if(type == SecurityConstants.TYPE_PKCS12) {
    		this.provider = new Pkcs12KeyProvider(factory, keyData);
    	} else if(type == SecurityConstants.TYPE_PKCS12_PGP) {
    		this.provider = new PgpKeyProvider(factory, keyData, publicKeyFilepath);
    	} else {
    		throw new Exception("No Encryption Type");
    	}
    }

    public void sign(String pathToUnsignedDocument, String pathToSignedDocument) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, IOException, UnrecoverableEntryException, CertificateException, ParserConfigurationException, SAXException, MarshalException, XMLSignatureException, TransformerException {
        Document document = new DocumentReader(pathToUnsignedDocument).loadDocument();
        SignedInfo signedInfo = createSignature();
        KeyInfo keyInfo = provider.loadKeyInfo();
        PrivateKey privateKey = provider.loadPrivateKey();
        sign(document, privateKey, signedInfo, keyInfo);
        new DocumentWriter(pathToSignedDocument).writeDocument(document);
    }

    private void sign(Document document, PrivateKey privateKey, SignedInfo signedInfo, KeyInfo keyInfo) throws MarshalException, XMLSignatureException {
        DOMSignContext signContext = new DOMSignContext(privateKey, document.getDocumentElement());
        XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(signContext);
    }

    private SignedInfo createSignature() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA1, null);
        Transform transform = factory.newTransform(ENVELOPED, (TransformParameterSpec) null);
        Reference reference = factory.newReference(Entire_Document, digestMethod, singletonList(transform), null, null);
        SignatureMethod signatureMethod = factory.newSignatureMethod(RSA_SHA1, null);
        CanonicalizationMethod canonicalizationMethod = factory.newCanonicalizationMethod(INCLUSIVE, (C14NMethodParameterSpec) null);
        return factory.newSignedInfo(canonicalizationMethod, signatureMethod, singletonList(reference));
    }
}