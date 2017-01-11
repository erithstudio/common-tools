package com.erith.commontools.security.xmlsignature.algorithm;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.crypto.SecretKey;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import com.erith.commontools.security.encryption.algorithm.pgp.BCPGPUtils;
import com.erith.commontools.security.encryption.algorithm.pgp.PgpToX509;
import com.erith.commontools.security.xmlsignature.PrivateKeyData;
import com.erith.commontools.security.xmlsignature.PrivateKeyProvider;


import static java.util.Collections.singletonList;

public class PgpKeyProvider implements PrivateKeyProvider {

	private final XMLSignatureFactory factory;
	private PrivateKeyData keyData;
	private static String publicKeyFilepath;

	public PgpKeyProvider(XMLSignatureFactory factory, PrivateKeyData keyData, String publicKeyFilepath) throws Exception {
		this.factory = factory;
		this.keyData = keyData;
		this.publicKeyFilepath = publicKeyFilepath;
	}

	public KeyInfo loadKeyInfo() {
		try {
			X509Certificate certificate = BCPGPUtils.createPrivateKeyToX509(keyData.pathToKeystore, keyData.passphraseForKeystore);
			return createKeyInfoFactory(certificate);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private KeyInfo createKeyInfoFactory(X509Certificate certificate) {
		KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
		List<Serializable> x509Content = new ArrayList<Serializable>();
		x509Content.add(certificate.getSubjectX500Principal().getName());
		x509Content.add(certificate);
		X509Data data = keyInfoFactory.newX509Data(x509Content);
		return keyInfoFactory.newKeyInfo(singletonList(data));
	}

	public PrivateKey loadPrivateKey() {
		try {
			return BCPGPUtils.findPrivateKey(keyData.pathToKeystore, keyData.passphraseForKeystore);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public PublicKey loadPublicKey() {
		try {
			return BCPGPUtils.readPublicKey(publicKeyFilepath);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
