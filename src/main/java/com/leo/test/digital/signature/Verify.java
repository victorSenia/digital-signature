package com.leo.test.digital.signature;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Senchenko Victor on 11.11.2016.
 */
public class Verify extends General {
    public static void main(String... args) {
        args = new String[]{PUBLIC_KEY_FILE_NAME, SING_FILE_NAME, FILE_NAME};
        try {
            byte[] bytesToVerify = read(new FileInputStream(args[1]));
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            // TODO get public key from file or certificate from storage
            //            PublicKey publicKey = getPublicKey(args[0]);
            //            signature.initVerify(publicKey);
            Certificate certificate = getCertificate(ALIAS);
            signature.initVerify(certificate);
            update(signature, new FileInputStream(args[2]));
            System.out.println("signature verifies: " + signature.verify(bytesToVerify));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PublicKey getPublicKey(String file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encKey = read(new FileInputStream(file));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_PAIR_GENERATOR_ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }
}
