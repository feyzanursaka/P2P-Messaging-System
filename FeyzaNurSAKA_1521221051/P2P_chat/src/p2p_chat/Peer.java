/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package p2p_chat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Date;
import java.util.Formatter;
import java.util.Random;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;

/* 
 * @Teachers  Ömer KORÇAK
 * @author Feyza Nur Saka
 * @date 31/05/2020
 * @class BLM442E Computer System Security
 * @ID 1521221051
 */
public class Peer {
static KeyPair pair;
static PublicKey publicKey;
static PrivateKey privateKey;

static SecretKey secretKey;

static IvParameterSpec ivSpec;
static IvParameterSpec ivSpec2;


static byte[] IV;

    public static void main(String[] args) throws IOException, Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("> enter username & port # for this peer:");
        String[] setupValues = bufferedReader.readLine().split(" ");
//moved to update
//        KeyPair pair = generateKeyPair();
//        System.out.println("Public = " + pair.getPublic()); //public secretKey
//        System.out.println("Private = " + pair.getPrivate()); //private secretKey
//        
//        publicKey=pair.getPublic();
//        privateKey=pair.getPrivate();

//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(256);//change with 128
        
        //-----------------------------------------------------------------------------------  
        //2.generates necessary keys for encryption and Message Authentication Code (MAC), as well as initialization vector(s) (IV).
        // Generate Key
//        secretKey = keyGenerator.generateKey();
//        
//        // Generating IV.
//        IV = new byte[16];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(IV);
        //----------------------------------------------------------------------------------
        ServerThread serverThread = new ServerThread(setupValues[1]);
        serverThread.start();
        new Peer().updateListenToPeers(bufferedReader, setupValues[0], serverThread);
    }

    //Generate an RSA public-private secretKey pair. KA+ and KA-
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }
    //Encypt message m with KA-
        public static String encrypt2(String plainText, PrivateKey privateKey) throws Exception {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

            byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }
        //3.all the messages must be encrypted using CBC mode ---------------------------------------------
        public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception {
            //Get Cipher Instance
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
            //Create IvParameterSpec
            ivSpec = new IvParameterSpec(IV);
            //Create another IvParameterSpec for showing that the corresponding ciphertext chages for the same plaintext
            IvParameterSpec ivSpec2 = new IvParameterSpec(IV);
        
            //Initialize Cipher for ENCRYPT_MODE
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            //cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec2);

            //Perform Encryption
            byte[] cipherText1 = cipher.doFinal(plaintext);
            //byte[] cipherText2 = cipher.doFinal(plaintext);

        return cipherText1;
    }
      //----------------------------------------------------------------------------------------------------------
public static byte[] getSHA(String input) throws NoSuchAlgorithmException 
    {  
        // Static getInstance method is called with hashing SHA  
        MessageDigest md = MessageDigest.getInstance("SHA-256");  
        // digest() method called  
        // to calculate message digest of an input  
        // and return array of byte 
        return md.digest(input.getBytes(StandardCharsets.UTF_8));  
    } 
    //2. Message Authentication Code(MAC) and 3.HMAC
    public static byte[] mac_byte_message(String msg) throws NoSuchAlgorithmException, InvalidKeyException 
    {  
      //Creating a Mac object
      Mac mac = Mac.getInstance("HmacSHA256");
      //Initializing the Mac object
      mac.init(secretKey);
      //Computing the Mac
      byte[] bytes = msg.getBytes();      
      byte[] macResult = mac.doFinal(bytes);
      return macResult;
    } 
    
    public static String toHexString(byte[] hash) 
    { 
        // Convert byte array into signum representation  
        BigInteger number = new BigInteger(1, hash);  
        // Convert message digest into hex value 
        StringBuilder hexString = new StringBuilder(number.toString(16));  
        // Pad with leading zeros 
        while (hexString.length() < 32)  
        {  
            hexString.insert(0, '0');  
        }  
        return hexString.toString();  
    } 
    
    public void updateListenToPeers(BufferedReader bufferedReader, String username, ServerThread serverThread) throws Exception {
        System.out.println("> enter (space separated) hostname:port#");
        System.out.println(" peers to receive messages from (s to skip):");
        String input = bufferedReader.readLine();
        String[] inputValues = input.split(" ");
        if (!input.equals("s")) for (int i = 0; i < inputValues.length; i++) {
                String[] address = inputValues[i].split(":");
                Socket socket = null;
                try {
                    socket = new Socket(address[0], Integer.valueOf(address[1]));
                    new PeerThread(socket).start();
                } catch (Exception e) {
                    if (socket != null) socket.close();
                    else System.out.println("invalid input. skipping to next step");
                }
        }
        communicate(bufferedReader, username, serverThread);
    }

    public void communicate(BufferedReader bufferedReader, String username, ServerThread serverthread) throws NoSuchAlgorithmException, Exception {  
        
        try {
            System.out.println("> you can now communicate (e to exit, c to change)");
            boolean flag = true;
            while (flag) {
                //6.UPDATE KEYS
                        KeyPair pair = generateKeyPair();
                        System.out.println("Public = " + pair.getPublic()); //public secretKey
                        System.out.println("Private = " + pair.getPrivate()); //private secretKey
        
                        publicKey=pair.getPublic();
                        privateKey=pair.getPrivate();
                        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                        keyGenerator.init(256);//change with 128
                        //-----------------------------------------------------------------------------------  
                        //2.generates necessary keys for encryption and Message Authentication Code (MAC), as well as initialization vector(s) (IV).
                        // Generate Key
                        secretKey = keyGenerator.generateKey();
                        System.out.println("Secret Key = " + secretKey);
        
                        // Generating IV.
                        IV = new byte[16];
                        SecureRandom random = new SecureRandom();
                        random.nextBytes(IV);
                        System.out.println("IV = " + IV);
                        //----------------------------------------------------------------------------------
                String message = bufferedReader.readLine();
            
                if (message.equals("e")) {
                    flag = false;
                    break;
                }else if (message.equals("c")){
                    updateListenToPeers(bufferedReader, username, serverthread);
                } else {
                                            
                        //3.
                        byte[] cipherText = encrypt(message.getBytes(), secretKey, IV);
                        String ciphertext_ =Base64.getEncoder().encodeToString(cipherText);
                        
                        //4.
                        byte[] cipherTextwithhash = encrypt(mac_byte_message(message), secretKey, IV);
                        String ciphertextwithhash_ =Base64.getEncoder().encodeToString(cipherTextwithhash);
                        
                        byte[] byte_pubkey = publicKey.getEncoded();
                        String str_publickey = Base64.getEncoder().encodeToString(byte_pubkey);
                        
                        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                        
                        String encodedIv = Base64.getEncoder().encodeToString(IV);
                    
                        String hmac=Base64.getEncoder().encodeToString(mac_byte_message(message));
                        
                        //creating nonce
                        long timestamp = new Date().getTime() / 1000;
                        String nonce = Long.toString( timestamp );    
                        //encrypt nonce with private key
                        String nonce_ = encrypt2(nonce, privateKey);
                        
                        StringWriter stringWriter = new StringWriter();
                        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                                
                                //sends the username to the other party
                                .add("username", username)
                                
                                //----------------------------------------------------------------------------------------------------------
                                //1.HANSHAKING (nonce, encrypted nonce, public key to decrypt)
                                //client sends nonce to make sure who the sender is when the message arrives
                                .add("nonce", nonce)
                                //When nonce arrives, the client encrypt with his private key and sends it to the other party.
                                .add("encrypted_nonce", nonce_)
                                //client uses the public key of the other clients to decrypt the encrypted nonce 
                                .add("public", str_publickey)  
                                
                                //-----------------------------------------------------------------------------------------------------------
                                
                                //3. Sends encrypted message (2.with the IV and secretKey generated in the previous step)
                                .add("encrypted", ciphertext_)  
                                .add("message", message)  
                                .add("secretKey", encodedKey)   
                                .add("iv", encodedIv)                                  
                                //-----------------------------------------------------------------------------------------------------------

                                //4.INTEGRITY CHECK with using hashing (HMAC)
                                .add("hmac", hmac)  
                                .add("encryptedwithhash", ciphertextwithhash_) 
                                //-----------------------------------------------------------------------------------------------------------
                                
                                .build());
                        serverthread.sendMessage(stringWriter.toString());
                    }
                }
                
            System.exit(0);
        } catch (Exception e) {
        }
    }
}
