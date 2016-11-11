package com.leo.test.digital.signature;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

/**
 * Created by Senchenko Victor on 11.11.2016.
 */
public class General {
    protected static final char[] STORE_PASSWORD = "test".toCharArray();

    protected static final char[] ALIAS_PASSWORD = "testtest".toCharArray();

    protected static final String ALIAS = "test";

    protected static final String STORE = "test.jks";

    protected static final String FILE_NAME = "pom.xml";

    protected static final String SING_FILE_NAME = "sing_of_file";

    protected static final String PUBLIC_KEY_FILE_NAME = "suePublicKey";

    protected static final String PRIVATE_KEY_FILE_NAME = "suePrivateKey";

    // SecureRandom Algorithms: [WINDOWS-PRNG, SHA1PRNG]
    protected static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

    // Providers: [SUN, SunRsaSign, SunEC, SunJSSE, SunJCE, SunJGSS, SunSASL, XMLDSig, SunPCSC, SunMSCAPI]
    protected static final String SECURE_RANDOM_PROVIDER = "SUN";

    // Signature Algorithms: [NONEWITHDSA, SHA384WITHECDSA, SHA224WITHDSA, SHA256WITHRSA, MD5WITHRSA, SHA1WITHRSA, SHA512WITHRSA, MD2WITHRSA, SHA256WITHDSA, SHA1WITHECDSA, MD5ANDSHA1WITHRSA, SHA224WITHRSA, NONEWITHECDSA, NONEWITHRSA, SHA256WITHECDSA, SHA224WITHECDSA, SHA384WITHRSA, SHA512WITHECDSA, SHA1WITHDSA]
    protected static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    // Providers: [SUN, SunRsaSign, SunEC, SunJSSE, SunJCE, SunJGSS, SunSASL, XMLDSig, SunPCSC, SunMSCAPI]
    protected static final String SIGNATURE_PROVIDER = "SUN";

    // KeyPairGenerator Algorithms: [RSA, DSA, DIFFIEHELLMAN, EC]
    protected static final String KEY_PAIR_GENERATOR_ALGORITHM = "EC";

    // Providers: [SUN, SunRsaSign, SunEC, SunJSSE, SunJCE, SunJGSS, SunSASL, XMLDSig, SunPCSC, SunMSCAPI]
    protected static final String KEY_PAIR_GENERATOR_PROVIDER = "SunEC";

    // KeyStore Types: [JKS, JCEKS, PKCS12, CASEEXACTJKS, DKS, WINDOWS-ROOT, WINDOWS-MY]
    protected static final String KEY_STORE_TYPE = "JKS";

    // CertificateFactory Types: [X.509]
    protected static final String CERTIFICATE_FACTORY_TYPE = "X.509";

    protected static final int KEY_SIZE = 571;

    protected static KeyStore keyStore;

    static {
        try {
            keyStore = getKeyStore();
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String... args) {
        Sign.main(args);
        Verify.main(args);
    }

    protected static void update(Signature signature, InputStream inputStream) throws IOException, SignatureException {
        try (BufferedInputStream bufin = new BufferedInputStream(inputStream)) {
            byte[] buffer = new byte[2048];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                signature.update(buffer, 0, len);
            }
        }
    }

    protected static byte[] read(InputStream inputStream) throws IOException {
        byte[] bytes = null;
        try {
            bytes = new byte[inputStream.available()];
            inputStream.read(bytes);
        } finally {
            inputStream.close();
        }
        return bytes;
    }

    protected static void save(byte[] bytes, OutputStream outputStream) throws IOException {
        try {
            outputStream.write(bytes);
        } finally {
            outputStream.close();
        }
    }

    protected static PrivateKey getPrivateKey(InputStream inputStream, char[] storePass, String alias, char[] keyPass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return (PrivateKey) keyStore.getKey(alias, keyPass);
    }

    protected static Certificate getCertificate(InputStream inputStream, char[] storePass, String alias) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return keyStore.getCertificate(alias);
    }

    private static KeyStore getKeyStore(InputStream inputStream, char[] storePass) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream)) {
            keyStore.load(bufferedInputStream, storePass);
        }
        return keyStore;
    }

    private static KeyStore getKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        return getKeyStore(new FileInputStream(STORE), STORE_PASSWORD);
    }

    private static Certificate getCertificate(InputStream inputStream) throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_FACTORY_TYPE);
        try (BufferedInputStream stream = new BufferedInputStream(inputStream)) {
            return certificateFactory.generateCertificate(stream);
        }
    }

    protected static void storeKey(OutputStream outputStream, char[] storePass, String alias, char[] keyPass, PrivateKey key, Certificate[] chain) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        keyStore.setKeyEntry(alias, key, keyPass, chain);
        try (BufferedOutputStream stream = new BufferedOutputStream(outputStream)) {
            keyStore.store(stream, storePass);
        }
    }
    //
    //    public static void generateCertificate(KeyPair keyPair) {
    //        try {
    //            KeyStore keyStore = KeyStore.getInstance("JKS");
    //            keyStore.load(new FileInputStream("mytestkey.jks"), "password".toCharArray());
    //
    //            CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
    //            gen.generate(1024);
    //
    //            Key key = gen.getPrivateKey();
    //            X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);
    //
    //            X509Certificate[] chain = new X509Certificate[1];
    //            chain[0] = cert;
    //
    //            keyStore.setKeyEntry("mykey", key, "password".toCharArray(), chain);
    //
    //            keyStore.store(new FileOutputStream("mytestkey.jks"), "password".toCharArray());
    //        } catch (Exception ex) {
    //            ex.printStackTrace();
    //        }
    //        try {
    //            KeyStore keyStore = KeyStore.getInstance("JKS");
    //            keyStore.load(new FileInputStream("mytestkey.jks"), "password".toCharArray());
    //
    //            CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
    //            gen.generate(1024);
    //
    //            X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=SINGLE_CERTIFICATE"), (long) 365 * 24 * 3600);
    //
    //            keyStore.setCertificateEntry("single_cert", cert);
    //
    //            keyStore.store(new FileOutputStream("mytestkey.jks"), "password".toCharArray());
    //        } catch (Exception ex) {
    //            ex.printStackTrace();
    //        }
    //    }
}
