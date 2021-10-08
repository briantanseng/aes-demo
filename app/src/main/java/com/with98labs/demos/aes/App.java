/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package com.with98labs.demos.aes;

public class App {

    public static void main(String[] args) throws Exception {

        System.out.println("Decryption Demo");
        runDecryptionDemo();
        System.out.println();
        System.out.println("Encryption Demo");
        runEncryptionDemo();

    }

    private static void runEncryptionDemo() {
        // FIX ME!
        final String secretKey = "Secret Passphrase";
        String originalString = "The quick brown fox jumps over the lazy dog.";

        String encryptedString = AES.encrypt(originalString, secretKey);

        System.out.println("original  = "+originalString);
        System.out.println("encrypted = "+encryptedString);

    }

    private static void runDecryptionDemo() {
        final String secretKey = "Secret Passphrase";

        String originalString = "The quick brown fox jumps over the lazy dog.";

        // Encrypted string came from crypto-js:
        // var CryptoJS = require("crypto-js");
        // var secretKey = 'Secret Passphrase';
        // var message = 'The quick brown fox jumps over the lazy dog.';
        // var encryptedString = CryptoJS.AES.encrypt(message, secretKey);
        String encryptedString = "U2FsdGVkX1/4wx2gw2HZDUN+IK1hHC3qIDWU5LSAFbwgE/RwTrzhw2HqVlxAgxNOfmXAIILFih/+hSl7ZXRDxw==";
        String decryptedString = AES.decrypt(encryptedString, secretKey) ;

        System.out.println("original  = "+originalString);
        System.out.println("encrypted = "+encryptedString);
        System.out.println("decrypted = "+decryptedString);
    }

}