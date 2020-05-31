/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package p2p_chat;

import static com.sun.org.apache.bcel.internal.classfile.Utility.toHexString;
import com.sun.xml.internal.ws.commons.xmlutil.Converter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import static p2p_chat.Peer.mac_byte_message;
import static p2p_chat.Peer.pair;
import static p2p_chat.Peer.toHexString;

/**
 *
 * @author Feyza Nur Saka
 */
public class PeerThread extends Thread {

    JsonObject jsonObject;
    private BufferedReader bufferedReader;

    public PeerThread(Socket socket) throws IOException {
        bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    //Decrypt message m with KA+
    public static byte[] decrypt(JsonObject jsonObject,byte[] ciphertext) throws Exception {
        
        //received secret key to decrypt the received encrypted message
        String secretKey = jsonObject.getString("secretKey");
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        //received iv to decrypt the received encrypted message
        String iv = jsonObject.getString("iv");
        byte[] iv_ = Base64.getDecoder().decode(iv);
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(originalKey.getEncoded(), "AES");
        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(iv_);
        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        //Perform Decryption
        byte[] decryptedText = cipher.doFinal(ciphertext);
        return decryptedText;
    }


    public static byte[] mac_byte_message(JsonObject jsonObject, String msg) throws NoSuchAlgorithmException, InvalidKeyException {
        String secretKey = jsonObject.getString("secretKey");
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        //Creating a Mac object
        Mac mac = Mac.getInstance("HmacSHA256");

        //Initializing the Mac object
        mac.init(originalKey);

        //Computing the Mac
        byte[] bytes = msg.getBytes();
        byte[] macResult = mac.doFinal(bytes);

        //System.out.println("Mac result:");
        //System.out.println(new String(macResult));
        return macResult;
    }

    public static byte[] getSHA(String input) throws NoSuchAlgorithmException {
        // Static getInstance method is called with hashing SHA  
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // digest() method called  
        // to calculate message digest of an input  
        // and return array of byte 
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHexString(byte[] hash) {
        // Convert byte array into signum representation  
        BigInteger number = new BigInteger(1, hash);

        // Convert message digest into hex value  
        StringBuilder hexString = new StringBuilder(number.toString(16));

        // Pad with leading zeros 
        while (hexString.length() < 32) {
            hexString.insert(0, '0');
        }

        return hexString.toString();
    }

    //I decrypted the file and showed that it is the same as the original file with the isSame() method.
    public static Boolean isSame(String plainText, String decryptedText) {
        boolean a = false;
        if (plainText.equals(decryptedText)) {
            a = true;
        }
        return a;
    }

    //received encrypted message
    public static byte[] ciphertext_(JsonObject jsonObject) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String ciphertext = jsonObject.getString("encrypted");
        byte[] ciphertext_ = Base64.getDecoder().decode(ciphertext);
        return ciphertext_;
    }
    //received encrypted nonce with private key of other client
//Decrypt nonce m with KA+

    public static String decrypt2(String cipherText, PublicKey publicKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }
    
    public static String decrypted_nonce(JsonObject jsonObject) throws NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        //To decrypt received message with received public ip   
        String publicKey = jsonObject.getString("public");
        byte[] byte_pubkey = Base64.getDecoder().decode(publicKey);
        PublicKey public_Key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(byte_pubkey));
        String encrypted_nonce = jsonObject.getString("encrypted_nonce");
        String decrypted_nonce = decrypt2(encrypted_nonce, public_Key);
        return decrypted_nonce;
    }

    public void run() {
        boolean flag = true;
        while (flag) {
            try {
                jsonObject = Json.createReader(bufferedReader).readObject();
                if (jsonObject.containsKey("username")) {

                    //1.HANDSHAKING
                    //received nonce and decrypt with public key  
                    String nonce = jsonObject.getString("nonce");
                    Boolean isSame_nonce = isSame(nonce, decrypted_nonce(jsonObject));

                    //2.USING GENERATED KEYS AND 3.MESSAGE DECRYPTION
                    //decrypt the encrypted message with secret key and iv 
                    String ciphertext = jsonObject.getString("encrypted");
                    byte[] ciphertext_ = Base64.getDecoder().decode(ciphertext);
                    byte[] decryptedMessage = decrypt(jsonObject,ciphertext_);
                    String decryptedMessage_=new String(decryptedMessage);
                    //String decryptedMessage_=Base64.getEncoder().encodeToString(decryptedMessage);

                    //4.INTEGRITY CHECK with using hashing (HMAC) 
                    //confidentality, authentication, integrity
                    String ciphertext_withhash = jsonObject.getString("encryptedwithhash");
                    byte[] ciphertext_withhash_ = Base64.getDecoder().decode(ciphertext_withhash);
                    byte[] decryptedMessage_withhash = decrypt(jsonObject,ciphertext_withhash_);
                    String decryptedMessage_withhash_=Base64.getEncoder().encodeToString(decryptedMessage_withhash);
                    String message = jsonObject.getString("message");
                    byte [] hmac = mac_byte_message(jsonObject, message);
                    String hmac_=Base64.getEncoder().encodeToString(hmac);  
                    Boolean isSame = isSame(hmac_, decryptedMessage_withhash_);

                    System.out.println("["+jsonObject.getString("username")+ "]" 
                                    + "\nnonce is : " + isSame_nonce
                                    + "\nencrypted : " + toHexString(decryptedMessage_withhash)
                                    + "\ndecryptedText : " + decryptedMessage_
                                    + "\nintegrity ensure : " + isSame
                    );  
                }
                
            } catch (Exception e) {
                flag = false;
                interrupt();
            }
        }
    }
}
