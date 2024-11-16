package org.example;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordSlowHashing {

    // Hash password using bcrypt.
    public static String hashPassword(String password) {

        return BCrypt.hashpw(password, BCrypt.gensalt(12)); // 12 is the cost factor
    }

    // Verify password.
    public static boolean verifyPassword(String password, String hashedPassword) {

        return BCrypt.checkpw(password, hashedPassword);
    }

    public static void main(String[] args) {

        String password = "MySecurePassword";

        // Hash the password.
        String hashedPassword = hashPassword(password);
        System.out.println("BCrypt Hashed Password: " + hashedPassword);

        // Verify the password.
        boolean isPasswordValid = verifyPassword(password, hashedPassword);
        System.out.println("Password Verified: " + isPasswordValid);
    }
}

