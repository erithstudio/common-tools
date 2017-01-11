package com.erith.commontools.security.encryption.algorithm.pgp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;

public class BCPGPUtils {

    /** Security provider: Bouncy Castle. */
    public static final String PROVIDER = "BC";

    /** The fingerprint calculator to use whenever it is needed. */
    static final KeyFingerPrintCalculator FP_CALC = new BcKeyFingerprintCalculator();

    /** Singleton for converting a PGP key to a JCA key. */
    private static JcaPGPKeyConverter sKeyConverter;

    static {
        Security.addProvider(new BouncyCastleProvider());

        if (sKeyConverter == null)
            sKeyConverter = new JcaPGPKeyConverter().setProvider(BCPGPUtils.PROVIDER);
    }

    public static PublicKey readPublicKey(String publicKeyFilePath) throws Exception {
        return readPGPPublicKey(publicKeyFilePath).getKey(PROVIDER);
    }

    public static PGPPublicKey readPGPPublicKey(String publicKeyFilePath) throws Exception {

        InputStream in = new FileInputStream(new File(publicKeyFilePath));

        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);
        PGPPublicKey key = null;

        Iterator rIt = pgpPub.getKeyRings();
        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();
            boolean encryptionKeyFound = false;

            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();
                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException(
                    "Can't find encryption key in key ring.");
        }

        return key;
    }

    public static PGPPublicKey readPGPPublicKey(String publicKeyFilePath, long keyId) throws IOException, PGPException {

        InputStream in = new FileInputStream(new File(publicKeyFilePath));

        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);
        PGPPublicKey key = null;

        Iterator rIt = pgpPub.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();
            boolean encryptionKeyFound = false;

            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();
                long keyid = k.getKeyID();
                if (keyid == keyId) {
                    key = k;
                }
                //if (k.isEncryptionKey()) {
                //	key = k;
                //}
            }
        }

        if (key == null) {
            throw new IllegalArgumentException(
                    "Can't find encryption key in key ring.");
        }

        return key;
    }

    public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException, NoSuchProviderException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(pass, "BC");
    }

    public static PrivateKey findPrivateKey(String signingPrivateKeyFilePath, char[] signingPrivateKeyPassword) throws Exception {
        InputStream keyInputStream = new FileInputStream(new File(signingPrivateKeyFilePath));
        PGPSecretKey secretKey = BCPGPUtils.findSecretKey(keyInputStream);
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(signingPrivateKeyPassword, PROVIDER);
        return privateKey.getKey();
    }

    public static X509Certificate createPrivateKeyToX509(String signingPrivateKeyFilePath, char[] signingPrivateKeyPassword) throws Exception {
        InputStream keyInputStream = new FileInputStream(new File(signingPrivateKeyFilePath));
        PGPSecretKey secretKey = BCPGPUtils.findSecretKey(keyInputStream);
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(signingPrivateKeyPassword, "BC");
        return PgpToX509.createSelfSignedCert(secretKey, privateKey, null);
    }

    public static PGPSecretKey findSecretKey(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in);

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPSecretKey key = null;

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpSec.getKeyRings();

        while (key == null && rIt.hasNext()) {
            PGPSecretKeyRing kRing = (PGPSecretKeyRing) rIt.next();
            Iterator kIt = kRing.getSecretKeys();

            while (key == null && kIt.hasNext()) {
                PGPSecretKey k = (PGPSecretKey) kIt.next();

                if (k.isSigningKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException(
                    "Can't find signing key in key ring.");
        }
        return key;
    }

    static PrivateKey convertPrivateKey(PGPPrivateKey key) throws PGPException {
        return sKeyConverter.getPrivateKey(key);
    }

    static PublicKey convertPublicKey(PGPPublicKey key) throws PGPException {
        return sKeyConverter.getPublicKey(key);
    }

    private static int getKeyFlags(PGPPublicKey key) {
        @SuppressWarnings("unchecked")
        Iterator<PGPSignature> sigs = key.getSignatures();
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            PGPSignatureSubpacketVector subpackets = sig.getHashedSubPackets();
            if (subpackets != null)
                return subpackets.getKeyFlags();
        }
        return 0;
    }

    static boolean isSigningKey(PGPPublicKey key) {
        int keyFlags = getKeyFlags(key);
        return (keyFlags & PGPKeyFlags.CAN_SIGN) == PGPKeyFlags.CAN_SIGN;
    }
}