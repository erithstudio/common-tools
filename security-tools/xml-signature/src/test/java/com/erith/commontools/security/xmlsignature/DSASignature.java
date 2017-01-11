package com.erith.commontools.security.xmlsignature;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Test;

public class DSASignature {
	
	private static String originalFilepath = "output/dsa/originalFile.txt";
    private static String signatureFilepath = "output/dsa/sig";
    private static String publicKeyFilepath = "output/dsa/suepk";
    private static String privateKeyFilepath = "output/dsa/sueprk";

    public void signGenerateFile() {
        /* Generate a DSA signature */
        try {
	        // the rest of the code goes here
        	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        	SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        	keyGen.initialize(1024, random);
        	
        	KeyPair pair = keyGen.generateKeyPair();
        	PrivateKey priv = pair.getPrivate();
        	PublicKey pub = pair.getPublic();
        	
        	Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
        	dsa.initSign(priv);
        	
        	FileInputStream fis = new FileInputStream(originalFilepath);
        	BufferedInputStream bufin = new BufferedInputStream(fis);
        	byte[] buffer = new byte[1024];
        	int len;
        	while ((len = bufin.read(buffer)) >= 0) {
        	    dsa.update(buffer, 0, len);
        	};
        	bufin.close();
        	
        	byte[] realSig = dsa.sign();
        	
        	/* save the signature in a file */
        	FileOutputStream sigfos = new FileOutputStream(signatureFilepath);
        	sigfos.write(realSig);
        	sigfos.close();
        	
        	/* save the public key in a file */
        	byte[] pubkey = pub.getEncoded();
        	FileOutputStream pubkeyfos = new FileOutputStream(publicKeyFilepath);
        	pubkeyfos.write(pubkey);
        	pubkeyfos.close();
        	
        	/* save the public key in a file */
        	byte[] prikey = priv.getEncoded();
        	FileOutputStream prikeyfos = new FileOutputStream(privateKeyFilepath);
        	prikeyfos.write(prikey);
        	prikeyfos.close();
        	
        } catch (Exception e) {
        	e.printStackTrace();
            System.err.println("Caught exception " + e.toString());
        }
    }
	
	@Test
    public void signFile() {

		try {
        	FileInputStream keyfis = new FileInputStream(privateKeyFilepath);
        	byte[] encKey = new byte[keyfis.available()];
        	keyfis.read(encKey);
        	keyfis.close();

        	PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);

        	KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        	PrivateKey priv = keyFactory.generatePrivate(privKeySpec);
        	
        	Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
        	dsa.initSign(priv);
        	
        	FileInputStream fis = new FileInputStream(originalFilepath);
        	BufferedInputStream bufin = new BufferedInputStream(fis);
        	byte[] buffer = new byte[1024];
        	int len;
        	while ((len = bufin.read(buffer)) >= 0) {
        	    dsa.update(buffer, 0, len);
        	};
        	bufin.close();
        	
        	byte[] realSig = dsa.sign();
        	
        	/* save the signature in a file */
        	FileOutputStream sigfos = new FileOutputStream(signatureFilepath);
        	sigfos.write(realSig);
        	sigfos.close();
        	
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
	
	@Test
	public void verifyFile(){
		
		 /* Verify a DSA signature */
        try {
        	// the rest of the code goes here
        	FileInputStream keyfis = new FileInputStream(publicKeyFilepath);
        	byte[] encKey = new byte[keyfis.available()];  
        	keyfis.read(encKey);

        	keyfis.close();
        	
        	X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
        	KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
        	PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        	
        	FileInputStream sigfis = new FileInputStream(signatureFilepath);
        	byte[] sigToVerify = new byte[sigfis.available()]; 
        	sigfis.read(sigToVerify);
        	sigfis.close();
        	
        	Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        	sig.initVerify(pubKey);
        	
        	FileInputStream datafis = new FileInputStream(originalFilepath);
        	BufferedInputStream bufin = new BufferedInputStream(datafis);

        	byte[] buffer = new byte[1024];
        	int len;
        	while (bufin.available() != 0) {
        	    len = bufin.read(buffer);
        	    sig.update(buffer, 0, len);
        	};

        	bufin.close();
        	
        	boolean verifies = sig.verify(sigToVerify);

        	System.out.println("signature verifies: " + verifies);
        	
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
	}
	
}