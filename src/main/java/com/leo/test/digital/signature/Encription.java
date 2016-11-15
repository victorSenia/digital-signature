package com.leo.test.digital.signature;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

/**
 * Created by Senchenko Victor on 15.11.2016.
 */
public class Encription extends General {
    protected static final String ALIAS_ENCODE = "testencode";

    protected static final String SECRET_KEY_FILE_NAME = "sueSecretKey";

    protected static final String PREFIX_ENCODE = "encrypt_";

    protected static final String PREFIX_DECODE = "decrypt_";

    // KeyGenerator Algorithms: [RC2, SUNTLSKEYMATERIAL, HMACSHA384, DESEDE, BLOWFISH, ARCFOUR, HMACSHA256, HMACSHA224, HMACMD5, AES, HMACSHA512, DES, SUNTLSRSAPREMASTERSECRET, SUNTLSPRF, SUNTLSMASTERSECRET, HMACSHA1, SUNTLS12PRF]
    protected static final String KEY_GENERATOR_ALGORITHM = "AES";

    // Cipher Algorithms: [PBEWITHHMACSHA384ANDAES_128, AES_256/GCM/NOPADDING, AES_192/GCM/NOPADDING, PBEWITHHMACSHA512ANDAES_128, AES_256/CBC/NOPADDING, AES_256/ECB/NOPADDING, PBEWITHHMACSHA224ANDAES_256, AES_128/CBC/NOPADDING, AESWRAP_192, AESWRAP, PBEWITHMD5ANDDES, AES_192/CBC/NOPADDING, PBEWITHHMACSHA256ANDAES_256, PBEWITHHMACSHA1ANDAES_128, PBEWITHSHA1ANDRC4_128, AES_192/OFB/NOPADDING, AES_128/ECB/NOPADDING, DESEDEWRAP, AESWRAP_256, RC2, PBEWITHSHA1ANDRC4_40, RSA, AESWRAP_128, PBEWITHHMACSHA512ANDAES_256, AES_192/CFB/NOPADDING, DESEDE, AES_128/CFB/NOPADDING, AES_192/ECB/NOPADDING, BLOWFISH, ARCFOUR, AES_256/CFB/NOPADDING, AES, RSA/ECB/PKCS1PADDING, AES_128/OFB/NOPADDING, AES_128/GCM/NOPADDING, DES, PBEWITHHMACSHA256ANDAES_128, PBEWITHSHA1ANDDESEDE, PBEWITHSHA1ANDRC2_40, PBEWITHHMACSHA384ANDAES_256, AES_256/OFB/NOPADDING, PBEWITHSHA1ANDRC2_128, PBEWITHMD5ANDTRIPLEDES, PBEWITHHMACSHA1ANDAES_256, PBEWITHHMACSHA224ANDAES_128]
    protected static final String CIPHER_ALGORITHM = "AES";

    protected static final int KEY_SIZE = 128;

    // MessageDigest Algorithms: [SHA-384, SHA-224, SHA-256, MD2, SHA, SHA-512, MD5]
    //    SHA-384 get byte length 48
    //    SHA-224 get byte length 28
    //    SHA-256 get byte length 32
    //    MD2 get byte length 16
    //    SHA get byte length 20
    //    SHA-512 get byte length 64
    //    MD5 get byte length 16
    private static final String MESSAGE_DIGEST_ALGORITHM = "MD5";

    public static void main(String... args) {
        //        try {
        //            initial();
        //        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
        //            e.printStackTrace();
        //        }
        try {
            SecretKey key;
            // TODO key can be stored to file or store (checked on store JCEKS)
            //            secretKeyToFile();
            //            secretKeyToStore();
            // TODO key can be retrived from file, store or from string
            //            key = getKey();
            //            key = secretKeyFromFile();
            key = secretKeyFromString(SECRET_KEY_FILE_NAME);
            byte[] encrypt = crypt(Cipher.ENCRYPT_MODE, read(new FileInputStream(FILE_NAME)), key);
            save(encrypt, new FileOutputStream(PREFIX_ENCODE + FILE_NAME));
            // TODO key can be retrived from file, store or from string
            //            key = getKey();
            //            key = secretKeyFromFile();
            key = secretKeyFromString(SECRET_KEY_FILE_NAME);
            byte[] decrypt = crypt(Cipher.DECRYPT_MODE, read(new FileInputStream(PREFIX_ENCODE + FILE_NAME)), key);
            save(decrypt, new FileOutputStream(PREFIX_DECODE + FILE_NAME));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void initial() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
        SecretKey myDesKey = keygenerator.generateKey();
        Cipher desCipher;
        // Create the cipher
        desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        // Initialize the cipher for encryption
        desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);
        //sensitive information
        byte[] text = "No body can see me".getBytes();
        System.out.println("Text Bytes : " + Arrays.toString(text));
        System.out.println("Text : " + new String(text));
        // Encrypt the text
        byte[] textEncrypted = desCipher.doFinal(text);
        System.out.println("Text Encryted Bytes : " + Arrays.toString(textEncrypted));
        // Initialize the same cipher for decryption
        desCipher.init(Cipher.DECRYPT_MODE, myDesKey);
        // Decrypt the text
        byte[] textDecrypted = desCipher.doFinal(textEncrypted);
        System.out.println("Text Encryted : " + new String(textEncrypted));
        System.out.println("Text Bytes : " + Arrays.toString(textDecrypted));
        System.out.println("Text Decryted : " + new String(textDecrypted));
    }

    private static byte[] crypt(int mode, byte[] data, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = getCipher();
        cipher.init(mode, key);
        return cipher.doFinal(data);
    }

    private static Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(CIPHER_ALGORITHM);
    }

    private static SecretKey secretKeyToStore() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException {
        KeyGenerator keygenerator = KeyGenerator.getInstance(KEY_GENERATOR_ALGORITHM);
        keygenerator.init(KEY_SIZE, secureRandom);
        SecretKey secretKey = keygenerator.generateKey();
        storeKeyEntry(new FileOutputStream(STORE), STORE_PASSWORD, ALIAS_ENCODE, ALIAS_PASSWORD, secretKey);
        return secretKey;
    }

    private static SecretKey secretKeyToFile() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException {
        KeyGenerator keygenerator = KeyGenerator.getInstance(KEY_GENERATOR_ALGORITHM);
        keygenerator.init(KEY_SIZE, secureRandom);
        SecretKey secretKey = keygenerator.generateKey();
        save(secretKey.getEncoded(), new FileOutputStream(SECRET_KEY_FILE_NAME));
        return secretKey;
    }

    private static SecretKey secretKeyFromFile() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException {
        byte[] bytes = read(new FileInputStream(SECRET_KEY_FILE_NAME));
        return new SecretKeySpec(bytes, KEY_GENERATOR_ALGORITHM);
    }

    private static SecretKey getKey() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return getKey(ALIAS_ENCODE, ALIAS_PASSWORD);
    }

    private static SecretKey secretKeyFromString(String s) throws NoSuchAlgorithmException {
        return new SecretKeySpec(getHashOfString(s), KEY_GENERATOR_ALGORITHM);
    }

    private static byte[] getHashOfString(String s) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
        messageDigest.update(s.getBytes());
        return messageDigest.digest();
    }
}
