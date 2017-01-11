package com.erith.commontools.security.xmlsignature;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.net.URL;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;

public class XmlRoundtripTest {
	private static final Logger logger = Logger.getLogger(XmlRoundtripTest.class.getName());

    private XmlSigner signer;
    private XmlValidator validator;

    @Before
    public void createSignerWithKeyData() throws Exception {
        PrivateKeyData keyData = createKeyData();
        // this.signer = new XmlSigner(SecurityConstants.TYPE_PKCS12, keyData, null);
        this.signer = new XmlSigner(SecurityConstants.TYPE_PKCS12_PGP, keyData, getPathToFileOnClasspath("pgp/public.txt16a4b637-5dff-4fed-9d22-10f922109f26"));
    }

    @Before
    public void createValidatorWithKeyData() throws Exception {
        PrivateKeyData keyData = createKeyData();
        // this.validator = new XmlValidator(SecurityConstants.TYPE_PKCS12, keyData, null);
        this.validator = new XmlValidator(SecurityConstants.TYPE_PKCS12_PGP, keyData, getPathToFileOnClasspath("pgp/public.txt16a4b637-5dff-4fed-9d22-10f922109f26"));
    }

    private PrivateKeyData createKeyData() {
    	// Example using pkcs12
//        String pathToKeystore = getPathToFileOnClasspath("pkcs12/certificate.p12");
//        String passphraseForKeystore = "pass";
//        String passphraseForKey = "pass";
    	
    	// Example using pgp
    	String pathToKeystore = getPathToFileOnClasspath("pgp/private.txtc4a620c5-2596-4660-82e1-be8262c9ba6e");
        String passphraseForKeystore = "password";
        String passphraseForKey = "password";
        return new PrivateKeyData(pathToKeystore, passphraseForKeystore, passphraseForKey);
    }

    @Test
    public void canValidateAFileItSignedItself() throws Exception {
        String pathToInputFile = getPathToInputFile();
        logger.info("Read from: " + pathToInputFile);
        String pathToOutputFile = getPathToOutputFile();
        logger.info("Save to: " + pathToOutputFile);
        sign(pathToInputFile, pathToOutputFile);
        validate(pathToOutputFile);
    }

    private void sign(String pathToInputFile, String pathToOutputFile) throws Exception {
        signer.sign(pathToInputFile, pathToOutputFile);
    }

    private void validate(String pathToOutputFile) throws Exception {
        boolean isValid = validator.isValid(pathToOutputFile);
        assertThat(isValid, is(true));
    }

    private String getPathToInputFile() {
        return getPathToFileOnClasspath("unsignedFile.xml");
    }

    private String getPathToFileOnClasspath(String name) {
        URL unsignedXmlUrl = getClass().getClassLoader().getResource(name);
        return unsignedXmlUrl.getFile();
    }

    private String getPathToOutputFile() throws Exception {
        // File outputFile = new File("outputFilePkcs12.xml");
        File outputFile = new File("outputFilePGP.xml");
        return outputFile.getAbsolutePath();
    }
}
