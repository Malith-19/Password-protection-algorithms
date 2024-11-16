package org.example;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordSalting {

    // Generate a random salt.
    public static String generateSalt() {

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Hash the password with salt using SHA-256.
    public static String hashPasswordWithSalt(String password, String salt) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String saltedPassword = salt + password;
        byte[] hashBytes = md.digest(saltedPassword.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {

        String password = "MySecurePassword";
        String salt = generateSalt();

        // Hash with salt.
        String hashedPassword = hashPasswordWithSalt(password, salt);
        System.out.println("Salt: " + salt);
        System.out.println("Salted & Hashed Password: " + hashedPassword);

        // Repeating the salt+hash for the same password.
        String salt1 = generateSalt();
        String hashedPassword1 = hashPasswordWithSalt(password, salt1);
        System.out.println("Salt1: " + salt1);
        System.out.println("Salted & Hashed password for the same previous password: " + hashedPassword1);
    }
}

