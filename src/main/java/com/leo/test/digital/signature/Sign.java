package com.leo.test.digital.signature;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Created by Senchenko Victor on 11.11.2016.
 */
public class Sign extends General {

    //     "C:\Program Files\Java\jdk1.8.0_92\bin\keytool" -delete -v -keystore test.jks -storepass test -alias test
    //     "C:\Program Files\Java\jdk1.8.0_92\bin\keytool" -genkey -dname "CN=Leo, OU=Concept, O=Test, L=Kharkiv, ST=Ukraine, C=UA" -alias test -keyalg EC -keystore test.jks  -storepass test -keypass testtest -keysize 571
    // "C:\Program Files\Java\jdk1.8.0_92\bin\keytool" -list -v -keystore test.jks -storepass test -keypass password -alias testtest
    // "C:\Program Files\Java\jdk1.8.0_92\bin\keytool" -list -v -keystore test.jks -storepass test
    // "C:\Program Files\Java\jdk1.8.0_92\bin\keytool" -delete -v -keystore test.jks -storepass test -alias testtest

    private static SecureRandom secureRandom;

    private static void secureRandom() throws NoSuchProviderException, NoSuchAlgorithmException {
        secureRandom = SecureRandom.getInstanceStrong();
    }

    public static void main(String... args) {
        //        for (Provider provider : Security.getProviders()) {
        //            System.out.println(provider.getName());
        //            System.out.println(provider.values());
        //        }
        //        System.out.println("CertificateFactory Algorithms: " + Security.getAlgorithms("Certificate"));
        args = new String[]{FILE_NAME};
        try {
            secureRandom();
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            PrivateKey key;
            // TODO get private key from storage, file, or generate to storage (key and certificate) or files (private and public keys)
            key = getPrivateKey(new FileInputStream(STORE), STORE_PASSWORD, ALIAS, ALIAS_PASSWORD);
            //            key = fromFilePrivateKey();
            //            key = generateCertificate();
            //            key = generatePrivateKey();
            signature.initSign(key, secureRandom);
            update(signature, new FileInputStream(args[0]));
            byte[] sign = signature.sign();
            save(sign, new FileOutputStream(singName(args[0])));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair keyPair(int keysize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_GENERATOR_ALGORITHM);
        keyPairGenerator.initialize(keysize, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    private static PrivateKey generatePrivateKey() throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
        KeyPair keyPair = keyPair(KEY_SIZE);
        PublicKey publicKey = keyPair.getPublic();
        byte[] key = publicKey.getEncoded();
        save(key, new FileOutputStream(PUBLIC_KEY_FILE_NAME));
        PrivateKey privateKey = keyPair.getPrivate();
        key = privateKey.getEncoded();
        save(key, new FileOutputStream(PRIVATE_KEY_FILE_NAME));
        return privateKey;
    }

    private static PrivateKey fromFilePrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(read(new FileInputStream(PRIVATE_KEY_FILE_NAME)));
        return KeyFactory.getInstance("EC").generatePrivate(encodedKeySpec);
    }

    private static String singName(String name) {
        //        String adder = "sing_of_";
        //        name = name.replaceAll("\\.", "_");
        //        return adder + name;
        return SING_FILE_NAME;
    }

    private static PrivateKey generateCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidKeyException, NoSuchProviderException, SignatureException {
        CertAndKeyGen gen = new CertAndKeyGen(KEY_PAIR_GENERATOR_ALGORITHM, SIGNATURE_ALGORITHM);
        gen.generate(KEY_SIZE);
        PrivateKey key = gen.getPrivateKey();
        X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=Leo, OU=Concept, O=Test, L=Kharkiv, ST=Ukraine, C=UA"), (long) 365 * 24 * 3600);
        storeKey(new FileOutputStream(STORE), STORE_PASSWORD, ALIAS, ALIAS_PASSWORD, key, new X509Certificate[]{cert});
        return key;
    }

    private static X509Certificate createSignedCertificate(X509Certificate cetrificate, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
        try {
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();
            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, new CertificateIssuerName((X500Name) issuer));
            //No need to add the BasicContraint for leaf cert
            if (!cetrificate.getSubjectDN().getName().equals("CN=TOP")) {
                CertificateExtensions exts = new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }
            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);
            return outCert;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}
