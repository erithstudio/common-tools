package com.erith.commontools.security.encryption.algorithm.pgp;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

public class PgpToX509 {
    public final static String DN_COMMON_PART_O = "OpenPGP to X.509 Bridge";
    public final static String DN_COMMON_PART_OU = "OpenPGP Keychain cert";

    public static final String SC = BouncyCastleProvider.PROVIDER_NAME;
    public static final String BOUNCY_CASTLE_PROVIDER_NAME = SC;

    /**
     * Creates a self-signed certificate from a public and private key. The (critical) key-usage
     * extension is set up with: digital signature, non-repudiation, key-encipherment, key-agreement
     * and certificate-signing. The (non-critical) Netscape extension is set up with: SSL client and
     * S/MIME. A URI subjectAltName may also be set up.
     *
     * @param pubKey
     *            public key
     * @param privKey
     *            private key
     * @param subject
     *            subject (and issuer) DN for this certificate, RFC 2253 format preferred.
     * @param startDate
     *            date from which the certificate will be valid (defaults to current date and time
     *            if null)
     * @param endDate
     *            date until which the certificate will be valid (defaults to current date and time
     *            if null) *
     * @param subjAltNameURI
     *            URI to be placed in subjectAltName
     * @return self-signed certificate
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws IllegalStateException
     * @throws NoSuchProviderException
     * @throws CertificateException
     * @throws Exception
     *
     * @author Bruno Harbulot
     */
    public static X509Certificate createSelfSignedCert(PublicKey pubKey, PrivateKey privKey,
                                                       X509Name subject, Date startDate, Date endDate, String subjAltNameURI)
            throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, NoSuchProviderException {

        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

        certGenerator.reset();
        /*
         * Sets up the subject distinguished name. Since it's a self-signed certificate, issuer and
         * subject are the same.
         */
        certGenerator.setIssuerDN(subject);
        certGenerator.setSubjectDN(subject);

        /*
         * Sets up the validity dates.
         */
        if (startDate == null) {
            startDate = new Date(System.currentTimeMillis());
        }
        certGenerator.setNotBefore(startDate);
        if (endDate == null) {
            endDate = new Date(startDate.getTime() + (365L * 24L * 60L * 60L * 1000L));
//            Log.d(Constants.TAG, "end date is=" + DateFormat.getDateInstance().format(endDate));
        }

        certGenerator.setNotAfter(endDate);

        /*
         * The serial-number of this certificate is 1. It makes sense because it's self-signed.
         */
        certGenerator.setSerialNumber(BigInteger.ONE);
        /*
         * Sets the public-key to embed in this certificate.
         */
        certGenerator.setPublicKey(pubKey);
        /*
         * Sets the signature algorithm.
         */
        String pubKeyAlgorithm = pubKey.getAlgorithm();
        if (pubKeyAlgorithm.equals("DSA")) {
            certGenerator.setSignatureAlgorithm("SHA1WithDSA");
        } else if (pubKeyAlgorithm.equals("RSA")) {
            certGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
        } else {
            RuntimeException re = new RuntimeException("Algorithm not recognised: "  + pubKeyAlgorithm);
            System.out.println(re.getMessage());
            throw re;
        }

        /*
         * Adds the Basic Constraint (CA: true) extension.
         */
        certGenerator.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(true));

        /*
         * Adds the subject key identifier extension.
         */
        SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifierStructure(pubKey);
        certGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifier);

        /*
         * Adds the authority key identifier extension.
         */
        AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(pubKey);
        certGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                authorityKeyIdentifier);

        /*
         * Adds the subject alternative-name extension.
         */
        if (subjAltNameURI != null) {
            GeneralNames subjectAltNames = new GeneralNames(new GeneralName(
                    GeneralName.uniformResourceIdentifier, subjAltNameURI));
            certGenerator.addExtension(X509Extensions.SubjectAlternativeName, false,
                    subjectAltNames);
        }

        /*
         * Creates and sign this certificate with the private key corresponding to the public key of
         * the certificate (hence the name "self-signed certificate").
         */
        X509Certificate cert = certGenerator.generate(privKey);

        /*
         * Checks that this certificate has indeed been correctly signed.
         */
        cert.verify(pubKey);

        return cert;
    }

    /**
     * Creates a self-signed certificate from a PGP Secret Key.
     *
     * @param pgpSecKey
     *            PGP Secret Key (from which one can extract the public and private keys and other
     *            attributes).
     * @param pgpPrivKey
     *            PGP Private Key corresponding to the Secret Key (password callbacks should be done
     *            before calling this method)
     * @param subjAltNameURI
     *            optional URI to embed in the subject alternative-name
     * @return self-signed certificate
     * @throws PGPException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws CertificateException
     *
     * @author Bruno Harbulot
     */
    public static X509Certificate createSelfSignedCert(PGPSecretKey pgpSecKey, PGPPrivateKey pgpPrivKey, String subjAltNameURI) throws PGPException,
            NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, CertificateException {
        // get public key from secret key
        PGPPublicKey pgpPubKey = pgpSecKey.getPublicKey();

        System.out.println("Key ID: " + Long.toHexString(pgpPubKey.getKeyID() & 0xffffffffL));

        /*
         * The X.509 Name to be the subject DN is prepared. The CN is extracted from the Secret Key
         * user ID.
         */
        Vector<DERObjectIdentifier> x509NameOids = new Vector<DERObjectIdentifier>();
        Vector<String> x509NameValues = new Vector<String>();

        x509NameOids.add(X509Name.O);
        x509NameValues.add(DN_COMMON_PART_O);

        x509NameOids.add(X509Name.OU);
        x509NameValues.add(DN_COMMON_PART_OU);

        for (@SuppressWarnings("unchecked")
             Iterator<Object> it = (Iterator<Object>) pgpSecKey.getUserIDs(); it.hasNext();) {
            Object attrib = it.next();
            x509NameOids.add(X509Name.CN);
            x509NameValues.add("CryptoCall");
            // x509NameValues.add(attrib.toString());
        }

        /*
         * Currently unused.
         */
        System.out.print("User attributes: ");
        for (@SuppressWarnings("unchecked")
             Iterator<Object> it = (Iterator<Object>) pgpSecKey.getUserAttributes(); it.hasNext();) {
            Object attrib = it.next();
            System.out.println(" - " + attrib + " -- " + attrib.getClass());
        }

        X509Name x509name = new X509Name(x509NameOids, x509NameValues);

        System.out.println("Subject DN: " + x509name);

        /*
         * To check the signature from the certificate on the recipient side, the creation time
         * needs to be embedded in the certificate. It seems natural to make this creation time be
         * the "not-before" date of the X.509 certificate. Unlimited PGP keys have a validity of 0
         * second. In this case, the "not-after" date will be the same as the not-before date. This
         * is something that needs to be checked by the service receiving this certificate.
         */
        Date creationTime = pgpPubKey.getCreationTime();
        System.out.println("pgp pub key creation time=" + DateFormat.getDateInstance().format(creationTime));
        System.out.println("pgp valid seconds=" + pgpPubKey.getValidSeconds());
        Date validTo = null;
        if (pgpPubKey.getValidSeconds() > 0) {
            validTo = new Date(creationTime.getTime() + 1000L * pgpPubKey.getValidSeconds());
        }

        X509Certificate selfSignedCert = createSelfSignedCert(
                pgpPubKey.getKey(BOUNCY_CASTLE_PROVIDER_NAME), pgpPrivKey.getKey(),
                x509name, creationTime, validTo, subjAltNameURI);

        return selfSignedCert;
    }



    public static X509Certificate createCertificate(PGPKeyPair keyPair, byte[] publicKeyRingData)
            throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, NoSuchProviderException, PGPException, IOException, OperatorCreationException {

        X500NameBuilder x500NameBuilder = new X500NameBuilder(X500Name.getDefaultStyle());

    /*
     * The X.509 Name to be the subject DN is prepared.
     * The CN is extracted from the Secret Key user ID.
     */

        x500NameBuilder.addRDN(BCStyle.O, DN_COMMON_PART_O);

        PGPPublicKey publicKey = keyPair.getPublicKey();

        for (@SuppressWarnings("unchecked") Iterator<Object> it = publicKey.getUserIDs(); it.hasNext();) {
            Object attrib = it.next();
            x500NameBuilder.addRDN(BCStyle.CN, attrib.toString());
        }

        X500Name x509name = x500NameBuilder.build();

    /*
     * To check the signature from the certificate on the recipient side,
     * the creation time needs to be embedded in the certificate.
     * It seems natural to make this creation time be the "not-before"
     * date of the X.509 certificate.
     * Unlimited PGP keys have a validity of 0 second. In this case,
     * the "not-after" date will be the same as the not-before date.
     * This is something that needs to be checked by the service
     * receiving this certificate.
     */
        Date creationTime = publicKey.getCreationTime();
        Date validTo = null;
        if (publicKey.getValidSeconds()>0)
            validTo = new Date(creationTime.getTime() + 1000L * publicKey.getValidSeconds());

        return createCertificate(
                BCPGPUtils.convertPublicKey(publicKey),
                BCPGPUtils.convertPrivateKey(keyPair.getPrivateKey()),
                x509name,
                creationTime, validTo,
                null,
                publicKeyRingData);
    }

    /**
     * Creates a self-signed certificate from a public and private key. The
     * (critical) key-usage extension is set up with: digital signature,
     * non-repudiation, key-encipherment, key-agreement and certificate-signing.
     * The (non-critical) Netscape extension is set up with: SSL client and
     * S/MIME. A URI subjectAltName may also be set up.
     *
     * @param pubKey
     *            public key
     * @param privKey
     *            private key
     * @param subject
     *            subject (and issuer) DN for this certificate, RFC 2253 format
     *            preferred.
     * @param startDate
     *            date from which the certificate will be valid
     *            (defaults to current date and time if null)
     * @param endDate
     *            date until which the certificate will be valid
     *            (defaults to start date and time if null)
     * @param subjectAltNames
     *            URIs to be placed in subjectAltName
     * @return self-signed certificate
     */
    private static X509Certificate createCertificate(PublicKey pubKey,
                                                     PrivateKey privKey, X500Name subject,
                                                     Date startDate, Date endDate, List<String> subjectAltNames, byte[] publicKeyData)
            throws InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException,
            NoSuchProviderException, IOException, OperatorCreationException {

        /*
         * Sets the signature algorithm.
         */
        BcContentSignerBuilder signerBuilder;
        String pubKeyAlgorithm = pubKey.getAlgorithm();
        switch (pubKeyAlgorithm) {
            case "DSA": {
                AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                        .find("SHA1WithDSA");
                AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                        .find(sigAlgId);
                signerBuilder = new BcDSAContentSignerBuilder(sigAlgId, digAlgId);
                break;
            }
            case "RSA": {
                AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                        .find("SHA1WithRSAEncryption");
                AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                        .find(sigAlgId);
                signerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
                break;
            }
            default:
                throw new RuntimeException("Algorithm not recognised: " + pubKeyAlgorithm);
        }

        AsymmetricKeyParameter keyp = PrivateKeyFactory.createKey(privKey.getEncoded());
        ContentSigner signer = signerBuilder.build(keyp);

        /*
         * Sets up the validity dates.
         */
        if (startDate == null) {
            startDate = new Date(System.currentTimeMillis());
        }
        if (endDate == null) {
            endDate = startDate;
        }

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            /*
             * Sets up the subject distinguished name.
             * Since it's a self-signed certificate, issuer and subject are the
             * same.
             */
                subject,
            /*
             * The serial-number of this certificate is 1. It makes sense
             * because it's self-signed.
             */
                BigInteger.ONE,
                startDate,
                endDate,
                subject,
            /*
             * Sets the public-key to embed in this certificate.
             */
                SubjectPublicKeyInfo.getInstance(pubKey.getEncoded())
        );

        /*
         * Adds the Basic Constraint (CA: true) extension.
         */
        certBuilder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(true));

        /*
         * Adds the Key Usage extension.
         */
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.keyAgreement | KeyUsage.keyCertSign));

        /*
         * Adds the Netscape certificate type extension.
         */
//        certBuilder.addExtension(MiscObjectIdentifiers.netscapeCertType,
//                false, new NetscapeCertType(
//                        NetscapeCertType.sslClient | NetscapeCertType.smime));

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        /*
         * Adds the subject key identifier extension.
         */
        SubjectKeyIdentifier subjectKeyIdentifier =
                extUtils.createSubjectKeyIdentifier(pubKey);
        certBuilder.addExtension(Extension.subjectKeyIdentifier,
                false, subjectKeyIdentifier);

        /*
         * Adds the authority key identifier extension.
         */
        AuthorityKeyIdentifier authorityKeyIdentifier =
                extUtils.createAuthorityKeyIdentifier(pubKey);
        certBuilder.addExtension(Extension.authorityKeyIdentifier,
                false, authorityKeyIdentifier);

        /*
         * Adds the subject alternative-name extension.
         */
//        if (subjectAltNames != null && subjectAltNames.size() > 0) {
//            GeneralName[] names = new GeneralName[subjectAltNames.size()];
//            for (int i = 0; i < names.length; i++)
//                names[i] = new GeneralName(GeneralName.otherName,
//                        new XmppAddrIdentifier(subjectAltNames.get(i)));
//
//            certBuilder.addExtension(Extension.subjectAlternativeName,
//                    false, new GeneralNames(names));
//        }

        /*
         * Adds the PGP public key block extension.
         */
//        SubjectPGPPublicKeyInfo publicKeyExtension =
//                new SubjectPGPPublicKeyInfo(publicKeyData);
//        certBuilder.addExtension(SubjectPGPPublicKeyInfo.OID, false, publicKeyExtension);

        /*
         * Creates and sign this certificate with the private key
         * corresponding to the public key of the certificate
         * (hence the name "self-signed certificate").
         */
        X509CertificateHolder holder = certBuilder.build(signer);

        /*
         * Checks that this certificate has indeed been correctly signed.
         */
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        cert.verify(pubKey);

        return cert;
    }

//    /**
//     * A custom X.509 extension for a PGP public key.
//     * @author Daniele Ricci
//     */
//    class SubjectPGPPublicKeyInfo extends ASN1Object {
//
//        // based on UUID 24e844a0-6cbc-11e3-8997-0002a5d5c51b
//        final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("2.25.49058212633447845622587297037800555803");
//
//        private final DERBitString keyData;
//
//        public SubjectPGPPublicKeyInfo(byte[] publicKey) {
//            keyData = new DERBitString(publicKey);
//        }
//
////        @Override
////        public ASN1Primitive toASN1Primitive() {
////            return keyData;
////        }
//
//        public int hashCode() {
//            return 0;
//        }
//
//        public void encode(DEROutputStream var1) throws IOException {
//
//        }
//
//        public boolean asn1Equals(DERObject var1) {
//            return false;
//        }
//    }
//
//    class XmppAddrIdentifier extends DLSequence {
//        final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8.5");
//
//        XmppAddrIdentifier(String jid) {
//            super(new ASN1Encodable[] {
//                    OID,
//                    new DERUTF8String(jid)
//            });
//        }
//    }

}