package org.example;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class PasswordEncryption {

    private static final String ALGORITHM = "AES";

    // Encrypt password.
    public static String encrypt(String password, SecretKey secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt password.
    public static String decrypt(String encryptedPassword, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes);
    }

    // Generate AES Secret Key.
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static void main(String[] args) throws Exception {

        SecretKey secretKey = generateSecretKey();
        String password = "MySecurePassword";

        // Encrypt.
        String encryptedPassword = encrypt(password, secretKey);
        System.out.println("Encrypted Password: " + encryptedPassword);

        // Decrypt.
        String decryptedPassword = decrypt(encryptedPassword, secretKey);
        System.out.println("Decrypted Password: " + decryptedPassword);
    }
}

