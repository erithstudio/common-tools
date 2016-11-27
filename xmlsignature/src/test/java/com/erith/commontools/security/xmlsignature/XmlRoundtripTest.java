package com.erith.commontools.security.xmlsignature;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.net.URL;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class XmlRoundtripTest {
	private static final Logger logger = Logger.getLogger(XmlRoundtripTest.class.getName());

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    private XmlSigner signer;
    private XmlValidator validator;

    @Before
    public void createSignerWithKeyData() throws Exception {
        PrivateKeyData keyData = createKeyData();
        this.signer = new XmlSigner(keyData);
    }

    @Before
    public void createValidatorWithKeyData() throws Exception {
        PrivateKeyData keyData = createKeyData();
        this.validator = new XmlValidator(keyData);
    }

    private PrivateKeyData createKeyData() {
        String pathToKeystore = getPathToFileOnClasspath("certificate.p12");
        String passphraseForKeystore = "pass";
        String passphraseForKey = "pass";
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
        File outputFile = folder.newFile("outputFile");
        return outputFile.getAbsolutePath();
    }
}
