package com.erith.commontools.security.xmlsignature.algorithm.pgp;

import com.erith.commontools.security.encryption.algorithm.pgp.BCPGPDecryptor;
import com.erith.commontools.security.encryption.algorithm.pgp.BCPGPEncryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.net.URL;
import java.security.Security;

import static org.junit.Assert.assertTrue;

public class BCPGPTest {

    @Test
    public void encryptFile() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("pgp/test.gpg.pub");
        encryptor.encryptFile("pgp/test.txt", "pgp/test.txt.enc");
        assertTrue(true);
    }

    public void decryptFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("pgp/test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.decryptFile("pgp/test.txt.enc", "pgp/test.txt.dec");
        assertTrue(true);
    }

    public void encryptAndSignFile() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("pgp/test.gpg.pub");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath("pgp/wahaha.gpg.prv");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile("pgp/test.txt", "pgp/test.txt.signed.enc");
        assertTrue(true);
    }

    public void decryptSignedFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("pgp/test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("pgp/wahaha.gpg.pub");

        // this file is encrypted with weili's public key and signed using wahaha's private key
        decryptor.decryptFile("pgp/test.txt.signed.enc", "pgp/test.txt.signed.dec");
        assertTrue(true);
    }

    public void decryptSignedFile1() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("pgp/test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(getPathToFileOnClasspath("pgp/wahaha.gpg.pub"));

        // this file is encrypted with weili's public key and signed using wahaha's private key
        decryptor.decryptFile(getPathToFileOnClasspath("pgp/test.txt.signed.asc"), getPathToFileOnClasspath("pgp/test.txt.signed.dec1"));
        assertTrue(true);
    }

    public void decryptSignedFileWithoutSignatureVerification() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(getPathToFileOnClasspath("pgp/test.gpg.prv"));
        decryptor.setPassword("password");

        // this file is encrypted with weili's public key and signed using wahaha's private key
        decryptor.decryptFile(getPathToFileOnClasspath("pgp/test.txt.signed.asc"), getPathToFileOnClasspath("pgp/test.txt.signed.dec2"));
        assertTrue(true);
    }

    private String getPathToFileOnClasspath(String name) {
        URL unsignedXmlUrl = getClass().getClassLoader().getResource(name);
        return unsignedXmlUrl.getFile();
    }
}