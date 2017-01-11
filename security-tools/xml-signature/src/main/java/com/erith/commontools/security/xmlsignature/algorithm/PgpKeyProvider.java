//package com.erith.commontools.security.xmlsignature.algorithm.pgp;
//
//import java.io.BufferedReader;
//import java.io.ByteArrayInputStream;
//import java.io.ByteArrayOutputStream;
//import java.io.DataOutputStream;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.FileReader;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.OutputStream;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import java.security.Security;
//import java.security.cert.CertificateException;
//import java.util.Iterator;
//
//import javax.xml.crypto.dsig.XMLSignatureFactory;
//import javax.xml.crypto.dsig.keyinfo.KeyInfo;
//
//import com.erith.commontools.security.xmlsignature.PrivateKeyData;
//import com.erith.commontools.security.xmlsignature.PrivateKeyProvider;
//import org.bouncycastle.bcpg.ArmoredInputStream;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.openpgp.PGPCompressedData;
//import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
//import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
//import org.bouncycastle.openpgp.PGPEncryptedDataList;
//import org.bouncycastle.openpgp.PGPException;
//import org.bouncycastle.openpgp.PGPLiteralData;
//import org.bouncycastle.openpgp.PGPObjectFactory;
//import org.bouncycastle.openpgp.PGPOnePassSignatureList;
//import org.bouncycastle.openpgp.PGPPrivateKey;
//import org.bouncycastle.openpgp.PGPPublicKey;
//import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
//import org.bouncycastle.openpgp.PGPPublicKeyRing;
//import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
//import org.bouncycastle.openpgp.PGPSecretKey;
//import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
//import org.bouncycastle.openpgp.PGPUtil;
//
//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;
//
//public class PgpKeyProvider implements PrivateKeyProvider {
//
//	private static final String Keystore_Type_Pkcs12 = "pkcs12";
//	private final XMLSignatureFactory factory;
////	private final KeyStore.PrivateKeyEntry keyEntry;
////	private KeyStore keyStore;
//	private PrivateKeyData keyData;
//
//	private static PGPPrivateKey pgpPrivateKey;
//	private static PGPPublicKey pgpPublicKey;
//	private static String publicKeyFilepath;
//
//	public PgpKeyProvider(XMLSignatureFactory factory, PrivateKeyData keyData, String publicKeyFilepath) throws Exception {
//		this.factory = factory;
//		this.keyData = keyData;
//		this.publicKeyFilepath = publicKeyFilepath;
//
//		if (pgpPrivateKey == null) {
//
//			String TOKEN = "aprisma";
//			byte[] encdata = encrypt(TOKEN.getBytes());
//			System.out.println("Encrypted: " + encdata);
//			BASE64Encoder en = new BASE64Encoder();
//			String temp = en.encode(encdata);
//			System.out.println("Temp: " + temp);
//			byte[] newB = null;
//			BASE64Decoder en1 = new BASE64Decoder();
//			try {
//				newB = en1.decodeBuffer(temp);
//			} catch (Exception e) {
//				System.out.println("Exception: " + e);
//			}
//			System.out.println("byte array" + newB.length);
//			String result = decrypt(newB);
//			System.out.println("Decrypted: " + result);
//
//			PrivateKey pKey = readPrivateKey(this.keyData.pathToKeystore, this.keyData.passphraseForKey);
//		}
//
////		KeyFactory kf = KeyFactory.getInstance("RSA");
////		RSAPrivateKeySpec priv = kf.getKeySpec(pgpPrivateKey.getKey(), RSAPrivateKeySpec.class);
////		System.out.println(priv);
//
////		this.keyStore = loadKeystore();
////		this.keyEntry = loadKeyEntry();
//	}
//
//	static {
//		Security.addProvider(new BouncyCastleProvider());
//	}
//
//	public KeyInfo loadKeyInfo() {
//		return null;
//	}
//
//	public PrivateKey loadPrivateKey() {
//		return pgpPrivateKey.getKey();
//	}
//
//	public PublicKey loadPublicKey() {
//		try {
//			return pgpPublicKey.getKey("BC");
//		} catch (NoSuchProviderException e) {
//			e.printStackTrace();
//		} catch (PGPException e) {
//			e.printStackTrace();
//		}
//		return null;
//	}
//
//	//
//	// Public class method decrypt
//	//
//	public String decrypt(byte[] encdata) {
//		System.out.println("decrypt(): data length=" + encdata.length);
//		// ----- Decrypt the file
//		try {
//			ByteArrayInputStream bais = new ByteArrayInputStream(encdata);
//			FileInputStream privKey = new FileInputStream(keyData.pathToKeystore);
//			return _decrypt(bais, privKey, keyData.passphraseForKey);
//		} catch (Exception e) {
//			System.out.println(e.getMessage());
//			e.printStackTrace();
//		}
//		return null;
//	}
//
//	private PrivateKey readPrivateKey(String privateKeyPath, char[] keyPassword) throws IOException {
//
//        /*FileReader fileReader = new FileReader(privateKeyPath);
//        PEMParser keyReader = new PEMParser(fileReader);
//
//        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
//        PEMDecryptorProvider decryptionProv = new JcePEMDecryptorProviderBuilder().build(keyPassword);
//
//        Object keyPair = keyReader.readObject();
//        PrivateKeyInfo keyInfo;
//
//        if (keyPair instanceof PEMEncryptedKeyPair) {
//            PEMKeyPair decryptedKeyPair = ((PEMEncryptedKeyPair) keyPair).decryptKeyPair(decryptionProv);
//            keyInfo = decryptedKeyPair.getPrivateKeyInfo();
//        } else {
//            keyInfo = ((PEMKeyPair) keyPair).getPrivateKeyInfo();
//        }
//
//        keyReader.close();
//        return converter.getPrivateKey(keyInfo);*/
//
//		try {
//			ArmoredInputStream ais = new ArmoredInputStream(new FileInputStream(privateKeyPath));
//
//			KeyStore pkcs12Store = KeyStore.getInstance("PKCS12");
//	        pkcs12Store.load(ais, keyPassword);
//	        java.security.cert.Certificate[] chain = pkcs12Store.getCertificateChain("aprisma");
//		} catch (Exception ex) {
//			ex.printStackTrace();
//		}
//        return null;
//    }
//
//	//
//	// Public class method encrypt
//	//
//	public byte[] encrypt(byte[] data) {
//		try {
//			// ----- Read in the public key
//			pgpPublicKey = readPublicKeyFromCol(new FileInputStream(publicKeyFilepath));
//			System.out.println("Creating a temp file...");
//			// create a file and write the string to it
//			File tempfile = File.createTempFile("pgp", null);
//			FileOutputStream fos = new FileOutputStream(tempfile);
//			fos.write(data);
//			fos.close();
//			System.out.println("Temp file created at ");
//			System.out.println(tempfile.getAbsolutePath());
//			System.out.println("Reading the temp file to make sure that the bits were written\n--------------");
//			BufferedReader isr = new BufferedReader(new FileReader(tempfile));
//			String line = "";
//			while ((line = isr.readLine()) != null) {
//				System.out.println(line + "\n");
//			}
//			// find out a little about the keys in the public key ring
//			System.out.println("Key Strength = " + pgpPublicKey.getBitStrength());
//			System.out.println("Algorithm = " + pgpPublicKey.getAlgorithm());
//			System.out.println("Bit strength = " + pgpPublicKey.getBitStrength());
//			System.out.println("Version = " + pgpPublicKey.getVersion());
//			System.out.println("Encryption key = " + pgpPublicKey.isEncryptionKey() + ", Master key = "
//					+ pgpPublicKey.isMasterKey());
//			int count = 0;
//			for (java.util.Iterator iterator = pgpPublicKey.getUserIDs(); iterator.hasNext();) {
//				count++;
//				System.out.println((String) iterator.next());
//			}
//			System.out.println("Key Count = " + count);
//			ByteArrayOutputStream baos = new ByteArrayOutputStream();
//			_encrypt(tempfile.getAbsolutePath(), baos, pgpPublicKey);
//			System.out.println("encrypted text length=" + baos.size());
//			tempfile.delete();
//			return baos.toByteArray();
//		} catch (PGPException e) {
//			e.printStackTrace();
//			System.out.println(e.getUnderlyingException().toString());
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//		return null;
//	}
//
//	//
//	// Private class method readPublicKeyFromCol
//	//
//	private PGPPublicKey readPublicKeyFromCol(InputStream in) throws Exception {
//		PGPPublicKeyRing pkRing = null;
//		PGPPublicKeyRingCollection pkCol = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
//
//		System.out.println("key ring size=" + pkCol.size());
//		Iterator it = pkCol.getKeyRings();
//		while (it.hasNext()) {
//			pkRing = (PGPPublicKeyRing) it.next();
//			Iterator pkIt = pkRing.getPublicKeys();
//			while (pkIt.hasNext()) {
//				PGPPublicKey key = (PGPPublicKey) pkIt.next();
//				System.out.println("Encryption key = " + key.isEncryptionKey() + ", Master key = " + key.isMasterKey());
//				if (key.isEncryptionKey())
//					return key;
//			}
//		}
//		return null;
//	}
//
//	//
//	// Private class method _encrypt
//	//
//	private void _encrypt(String fileName, OutputStream out, PGPPublicKey encKey)
//			throws IOException, NoSuchProviderException, PGPException {
//		out = new DataOutputStream(out);
//		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//		System.out.println("creating comData...");
//		// get the data from the original file
//		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
//		PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
//		comData.close();
//		System.out.println("comData created...");
//		System.out.println("using PGPEncryptedDataGenerator...");
//		// object that encrypts the data
//		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(PGPEncryptedDataGenerator.CAST5,
//				new SecureRandom(), "BC");
//		cPk.addMethod(encKey);
//		System.out.println("used PGPEncryptedDataGenerator...");
//		// take the outputstream of the original file and turn it into a byte
//		// array
//		byte[] bytes = bOut.toByteArray();
//		System.out.println("wrote bOut to byte array...");
//		// write the plain text bytes to the armored outputstream
//		OutputStream cOut = cPk.open(out, bytes.length);
//		cOut.write(bytes);
//		cPk.close();
//		out.close();
//	}
//
//	//
//	// Private class method _decrypt
//	//
//	private String _decrypt(InputStream in, InputStream keyIn, char[] passwd) throws Exception {
//		in = PGPUtil.getDecoderStream(in);
//		try {
//			PGPObjectFactory pgpF = new PGPObjectFactory(in);
//			PGPEncryptedDataList enc;
//			Object o = pgpF.nextObject();
//			//
//			// the first object might be a PGP marker packet.
//			//
//			if (o instanceof PGPEncryptedDataList) {
//				enc = (PGPEncryptedDataList) o;
//			} else {
//				enc = (PGPEncryptedDataList) pgpF.nextObject();
//			}
//			//
//			// find the secret key
//			//
//			Iterator it = enc.getEncryptedDataObjects();
//			PGPPublicKeyEncryptedData pbe = null;
//			while (pgpPrivateKey == null && it.hasNext()) {
//				pbe = (PGPPublicKeyEncryptedData) it.next();
//				System.out.println("pbe id=" + pbe.getKeyID());
//				pgpPrivateKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
//			}
//			if (pgpPrivateKey == null) {
//				throw new IllegalArgumentException("secret key for message not found.");
//			}
//			InputStream clear = pbe.getDataStream(pgpPrivateKey, "BC");
//			PGPObjectFactory plainFact = new PGPObjectFactory(clear);
//			Object message = plainFact.nextObject();
//			if (message instanceof PGPCompressedData) {
//				PGPCompressedData cData = (PGPCompressedData) message;
//				PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
//				message = pgpFact.nextObject();
//			}
//			ByteArrayOutputStream baos = new ByteArrayOutputStream();
//			if (message instanceof PGPLiteralData) {
//				PGPLiteralData ld = (PGPLiteralData) message;
//				InputStream unc = ld.getInputStream();
//				int ch;
//				while ((ch = unc.read()) >= 0) {
//					baos.write(ch);
//				}
//			} else if (message instanceof PGPOnePassSignatureList) {
//				throw new PGPException("encrypted message contains a signed message - not literal data.");
//			} else {
//				throw new PGPException("message is not a simple encrypted file - type unknown.");
//			}
//			if (pbe.isIntegrityProtected()) {
//				if (!pbe.verify()) {
//					System.err.println("message failed integrity check");
//				} else {
//					System.err.println("message integrity check passed");
//				}
//			} else {
//				System.err.println("no message integrity check");
//			}
//			return baos.toString();
//		} catch (PGPException e) {
//			System.err.println(e);
//			if (e.getUnderlyingException() != null) {
//				e.getUnderlyingException().printStackTrace();
//			}
//		}
//		return null;
//	}
//
//	//
//	// Private class method findSecretKey
//	//
//	private PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
//			throws IOException, PGPException, NoSuchProviderException {
//		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
//		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
//		if (pgpSecKey == null) {
//			return null;
//		}
//		return pgpSecKey.extractPrivateKey(pass, "BC");
//	}
//
//	//
//	// Public class method readFile
//	//
//	public byte[] readFile(File file) throws IOException {
//		FileInputStream fis = new FileInputStream(file);
//		byte[] buf = new byte[4096];
//		int numRead = 0;
//		ByteArrayOutputStream baos = new ByteArrayOutputStream();
//		while ((numRead = fis.read(buf)) > 0) {
//			baos.write(buf, 0, numRead);
//		}
//		fis.close();
//		byte[] returnVal = baos.toByteArray();
//		baos.close();
//		return returnVal;
//	}
//
//	private KeyStore loadKeystore()
//			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
//		KeyStore keyStore = KeyStore.getInstance(Keystore_Type_Pkcs12);
//		FileInputStream keystoreStream = new FileInputStream(keyData.pathToKeystore);
//		char[] passphrase = keyData.passphraseForKeystore;
//		keyStore.load(keystoreStream, passphrase);
//		return keyStore;
//	}
//
////	private KeyStore.PrivateKeyEntry loadKeyEntry()
////			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
////		char[] passphrase = keyData.passphraseForKey;
////		String alias = keyStore.aliases().nextElement();
////		return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(passphrase));
////	}
//}
