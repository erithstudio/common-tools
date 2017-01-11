package com.erith.commontools.security.xmlsignature;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Test;

public class JKSSignature {
	// keytool -genkey -alias tomcat -keyalg RSA -keystore keystore.jks
    private static String originalFilepath = "output/jks/originalFile.txt";
    private static String signatureFilepath = "output/jks/sig";
    private static String publicKeyFilepath = "output/jks/suecert";
    private static String privateKeyFilepath = "output/jks/keystore.jks";
    private static char[] spass = "password".toCharArray();
    private static String alias = "tomcat";
    private static char[] kpass = "keystore".toCharArray();

	@Test
    public void signFile() { // Private Key Required

		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			FileInputStream ksfis = new FileInputStream(privateKeyFilepath); 
			BufferedInputStream ksbufin = new BufferedInputStream(ksfis);

			ks.load(ksbufin, spass);
			PrivateKey priv = (PrivateKey) ks.getKey(alias, kpass);
        	
        	Signature dsa = Signature.getInstance("SHA256withRSA"); 
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
        	
        	java.security.cert.Certificate cert = ks.getCertificate(alias);
        	byte[] encodedCert = cert.getEncoded();
        	
        	// Save the certificate in a file named "suecert" 
        	FileOutputStream certfos = new FileOutputStream(publicKeyFilepath);
        	certfos.write(encodedCert);
        	certfos.close();
        	
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
	
	@Test
	public void verifyFile(){ // Public Key Required
		
		 /* Verify a DSA signature */
        try {
        	
        	// the rest of the code goes here
        	FileInputStream certfis = new FileInputStream(publicKeyFilepath);
        	java.security.cert.CertificateFactory cf =
        	    java.security.cert.CertificateFactory.getInstance("X.509");
        	java.security.cert.Certificate cert =  cf.generateCertificate(certfis);
        	PublicKey pubKey = cert.getPublicKey();
        	
        	FileInputStream sigfis = new FileInputStream(signatureFilepath);
        	byte[] sigToVerify = new byte[sigfis.available()]; 
        	sigfis.read(sigToVerify);
        	sigfis.close();
        	
        	Signature sig = Signature.getInstance("SHA256withRSA");
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