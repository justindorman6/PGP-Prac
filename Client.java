import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.ArrayList;
import java.lang.Integer;
import java.lang.Boolean;
import java.io.DataInputStream;
import java.io.PrintStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.*;
import java.nio.file.*;
import java.util.zip.*;//for zipping
import javax.crypto.*;//for crypto
import java.security.*;//for crypto
import java.security.spec.*;
import javax.crypto.spec.*;
//new bouncy castle libs
import org.bouncycastle.openpgp.PGPPrivateKey;//pgp crypto
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
   * Group members:
   * Justin Dorman: DRMJUS001
   * Zachary Bresler: BRSZAC002
   * Chad Piha: PHXCHA001
   * Emil Kenguerli: KNGEMI001
*/
public class Client {

  private static final String SERVER_IP_ADDRESS =  "localhost"; //default host address
  private static String clientId;
  private static String userName;
  private static String hostName;
  private static int portNumber = 60123; //default port number
  private static DataOutputStream out;
  private static DataInputStream in;
  private static Socket clientSocket;
  private static String message;
  private static PGPSend pgpsend;
  private static PGPReceive pgpreceive;
  private static boolean sender;

  public Client () 
  {
      socketSetup(); //Sets up the socket

      
      Scanner keyboard = new Scanner(System.in);

      while(true)
      {
        //prompts user to be sender ot receiver, then enter username
        System.out.print("Do you wish to (s)end or (r)receive messages: ");
        String answer = keyboard.nextLine();
        System.out.print("Enter a username: ");
        String username = keyboard.nextLine();
        userName = username;
        if(answer.equalsIgnoreCase("s")) //if sender client
        {
          sender = true;
          pgpsend = new PGPSend(username); //creates PGP send instance - generates keys and certificate in constructor
          break;
        }
        else if(answer.equalsIgnoreCase("r")) //if receiver client
        {
          sender = false;
          pgpreceive = new PGPReceive(username); //create PGP receive instance - generates keys and certificate in constructor
          break;
        }
        else { //invalid inout
          System.out.println("Enter a valid response");
          continue;
        }
      }

      //Displays group interface - either create or join a chat room
      groupInterface(keyboard);


      //Displays chat interface - send or receive a message
      while (!clientSocket.isClosed()){
        System.out.println();
        chatInterface(keyboard);
      }
  }

  //sets up client socket to connect to the server on default host address and port number
  public void socketSetup () {
      try{

      InetAddress host = InetAddress.getLocalHost();
      hostName = host.getHostName();
      clientSocket = new Socket(SERVER_IP_ADDRESS, portNumber);
      out = new DataOutputStream(clientSocket.getOutputStream());
      in = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
      System.out.println("Connecting to " + hostName + " on port " + portNumber);
      System.out.println("Just connected to server: " + clientSocket.getRemoteSocketAddress());
      System.out.println();

    } catch(IOException e) {
      e.printStackTrace();
    }
  }

      /**
   * Function for chat room interface - create or join a group
   * Allows for input of username and password to create a new chat room or join an exisiting one
   */
  public static void groupInterface(Scanner keyboard){
    boolean valid = false;
    while(!valid){
      System.out.print("Do you wish to (c)reate or (j)oin a chat room: ");
      String groupInputStatus = keyboard.nextLine();
      if(groupInputStatus.equalsIgnoreCase("c")){
        System.out.print("Chat room name: ");
        String groupName = keyboard.nextLine();
        System.out.print("Password: ");
        String password = keyboard.nextLine();
        valid = sendGroupName(groupName, password, true);
        if(valid){
          break;
        }else{
          System.out.println("Group already exists");
        }
      }else if(groupInputStatus.equalsIgnoreCase("j")){
        System.out.print("Group name: ");
        String groupName = keyboard.nextLine();
        System.out.print("Password: ");
        String password = keyboard.nextLine();
        valid = sendGroupName(groupName, password, false);
        if(valid){
          break;
        }else{
          System.out.println("Incorrect group name or password");
        }
      }else{
        System.out.println("Enter a valid response");
      }
    }
  }

      /**
   * Function for chat interface
   * Calls the appropriate pgp process procedures in the relevant PGP instance (send or receive)
   */
  public static void chatInterface(Scanner keyboard){
    System.out.println();
    if(sender) //if sender client
    {
      System.out.println("Please enter a message to encrypt(/q to quit):");
      String message = keyboard.nextLine();
      if(message.equals("/q"))
      {
        quit();
      }
      else
      {

        // Procedures involved with sending a secure message
        String plaintext = userName + ": " + message;

        byte[] hash = pgpsend.generateHash(plaintext);
        byte[] encryptedHash = pgpsend.encryptHash(hash);
        byte[] authMessage = pgpsend.authenticatePlaintext(encryptedHash, plaintext);
        byte[] compMessage = pgpsend.compressMessage(authMessage);
        pgpsend.generateSecretKey();
        byte[] ciphertext = pgpsend.generateCiphertext(compMessage);
        pgpsend.generateIV();
        pgpsend.getKUS();
        byte[] encryptedKey = pgpsend.encryptSecretKey();
        byte[] finCiphertext = pgpsend.generateFinalCiphertext(encryptedKey, ciphertext);
        sendMessage(finCiphertext);
      }
    }

    else //if receiver client
    {
      System.out.println("Hit enter when ready to receive a message (/q to quit)");
      String selectedAction = keyboard.nextLine();
      if(selectedAction.equals("/q"))
      {
        quit();
      }
      else
      {
        //check authenticity of senders certificate/public key
        //if validated, unpack message, else, cease communication

        if(pgpreceive.validateCertificate())
        {
          //procedures involved with receving a secure message
          byte[] recEncryptedMessage = receiveMessage();
          if(recEncryptedMessage == null) System.out.print("No messages");
          else 
          {
            byte[] encryptedKey = pgpreceive.getEncrptedKeyPart(recEncryptedMessage);
            byte[] encPayload = pgpreceive.getEncryptedMessagePart(recEncryptedMessage);
            pgpreceive.decryptSharedKey(encryptedKey);
            byte[] compPayload = pgpreceive.decryptMessage(encPayload);
            byte[] payload = pgpreceive.decompressMessage(compPayload);
            byte[] signature = pgpreceive.getSignaturePart(payload);
            byte[] plaintext = pgpreceive.getPlaintext(payload);
            byte[] plaintextHash = pgpreceive.generatePlaintextHash(plaintext);
            pgpreceive.getKUC();
            byte[] recMessageHash = pgpreceive.decryptHash(signature);
            pgpreceive.authenticate(recMessageHash, plaintextHash);

          }
        }
        else //untrusted sender
        {
          System.out.print("Sender is not trusted, communication will be ceased");
          quit();
        }
  
      }
    }

  }

      /**
   * Function for sending a message in byte[] form
   */
  public static void sendMessage(byte[] finCipherText){
    try{
      out.writeUTF("client_out_message --true");
      out.writeInt(finCipherText.length);
      out.write(finCipherText);
    }catch(IOException e){
      System.out.println(e);
    }
  }

    /**
   * Function for receiving a message in byte[] form
   */
  public static byte[] receiveMessage(){
    try{
      while(in.available() > 0){
        String receivedMessage = in.readUTF();
        switch(receivedMessage){
          case "client_in_message --true":
            byte[] message = null;
            int msgLength = in.readInt();
            if (msgLength >0)
            {
              message = new byte[msgLength];
              in.readFully(message, 0, message.length);
            }
            return message;
        }
      }
    }catch(IOException e){
      System.out.println(e);
    }
    return null;
  }

      /**
   * Function for setting up or joining chat room
   */
  public static boolean sendGroupName(String groupName, String password, boolean newGroup){
    try{
      if(newGroup){
        out.writeUTF("set_group_name --new");
        out.writeUTF(groupName);
        out.writeUTF(password);
        String response = in.readUTF();
        return Boolean.parseBoolean(response);
      }else{
        out.writeUTF("set_group_name --existing");
        out.writeUTF(groupName);
        out.writeUTF(password);
        String response = in.readUTF();
        return Boolean.parseBoolean(response);
      }
    }catch(IOException e){
      System.out.println(e);
      return false;
    }
  }

  public static String getClientId(){
    return clientId;
  }

  //function for closing connection
  public static void quit(){
    try{
      clientSocket.close();
      System.out.println("Connection is now closed");
    }catch(IOException e){
      System.out.println(e);
    }
  }

  public static void main(String[] args)
  {
    Client c = new Client();
  }
}


class PGPSend {
  private String plaintext;
  private BufferedReader inputLine = null;
  private boolean closed = false; //Volatile variable?
  private PrivateKey KRC; //senders private key
  private PublicKey KUC; //senders public key
  private SecretKey secretKey;
  private SecretKeySpec k;
  private PublicKey KUS;//receivers public key
  private Cipher aescipher;
  private byte[] finCiphertext;
  private PrivateKey caPrivateKey;

    /**
   * Constructor that generates senders public and private key pair and certificate
   */
  public PGPSend (String username)
  {
      generateKeys();
      generateCertificate(username);
  }

    /**
   * Generate the public/private key pair for the sender (KRC, KUC)
   */
  public void generateKeys () {
    try {
      //create private and public keys for sender
      System.out.println("\nCREATING SENDER PRIVATE AND PUBLIC KEY PAIR:");
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(1024);
      KeyPair keys = keyGen.generateKeyPair();

      //get the key from the generator
      KRC = keys.getPrivate();
      KUC = keys.getPublic();

      //convert to bytes
      byte[] KUCArray = KUC.getEncoded();

      //write the public key to a file
      System.out.println("\tWriting sender's Public Key to file \"sender_public_key.txt\" \n");
      FileOutputStream fos = new FileOutputStream("sender_public_key.txt");
      fos.write(KUCArray);
      fos.close();
    }
    catch (Exception e) {
      System.err.println(e);
    }
  }


    /**
   * Generate the sender certificate - write to file
   * Following this, generate the sender signed certificate - write to file
   */
  public void generateCertificate(String username)
  {
    try {
      System.out.println("\nCREATING SENDER CERTIFICATE:");
      //convert username to bytes
      byte[] identityArray = username.getBytes(); 

      //convert sender public key to bytes
      byte[] KUCArray = KUC.getEncoded();

      System.out.println("\tGenerating certificate (sender username concatenated with public key)");

      //Concat bytes to create certificate
      byte[] certificate = new byte[identityArray.length + KUCArray.length];
      System.arraycopy(identityArray, 0, certificate, 0, identityArray.length);
      System.arraycopy(KUCArray, 0, certificate, identityArray.length, KUCArray.length);

      System.out.println("\tWriting certificate to file \"sender_certificate.txt\"\n");

      FileOutputStream fos = new FileOutputStream("sender_certificate.txt");
      fos.write(certificate);
      fos.close();

      System.out.println("\nCREATING SENDER SIGNED CERTIFICATE:");

      //sign certificate by generating hash of certificate and signing with CA private key
      byte[] hash = null;
      byte[] signedCertificate = null;

      System.out.println("\tHashing certificate");
      try {
      //CREATE A HASH OF THE CERTIFICATE
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(certificate);
      hash = md.digest();
      int mdValue = 0;
      for (int i = 0; i < hash.length; i++){
        mdValue += hash[i];
      }

      }
      catch (Exception e) {
        System.err.println(e);
      }

      //get CA private key from textfile
      
      try {
      System.out.println("\tReading in CA private key from file \"CA_private_key.txt\"");
      Path path = Paths.get("CA_private_key.txt");
      byte[] pKey = Files.readAllBytes(path);

      /* Generate private key. */
      PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(pKey);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      caPrivateKey = kf.generatePrivate(ks);

      }
      catch (Exception e) {
        System.err.println(e);
      }

      System.out.println("\tSigning hash with CA private key");
      try {
      Cipher RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      RSAcipher.init(Cipher.ENCRYPT_MODE, caPrivateKey);
      signedCertificate = RSAcipher.doFinal(hash);
      }
      catch (Exception e) {
        System.err.println(e);
      }


      //write signed certificate to file
      System.out.println("\tWriting signed certificate to file \"signed_certificate.txt\" \n");
      FileOutputStream fosSC = new FileOutputStream("signed_certificate.txt");
      fosSC.write(signedCertificate);
      fosSC.close();

    }

    catch (Exception e)
    {
      System.err.println(e);
    }
  }

    /*
  Generate Message digest
  */
  /**
   * Generates message digest (hash) of Plaintext
   * @param String Plaintext  plaintext to be encrypted
   * @return byte[] hash    hash of plaintext (using SHA-256)
   */
  public byte[] generateHash (String plaintext) {
    System.out.println("_SETTING UP AUTHENTICATION:_");
    byte[] hash = null;
    byte[] signedPlaintext = null;
    try {
      //CREATE A HASH OF THE MESSAGE
      System.out.println("\n\tCREATING MESSAGE DIGEST");
      System.out.println("\t\tPlaintext: " + plaintext);
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(plaintext.getBytes("UTF-8"));
      hash = md.digest();

      System.out.println("\t\tMessage Digest Size: " + hash.length);

      System.out.println("\t\tMessage Digest: [" + new String(hash)+"]");

    }
    catch (Exception e) {
      System.err.println(e);
    }
    return hash;
  }


    /**
   * Generates the digital signature by encrypting the hash with KRC (for authenticity)
   * @param  byte[] hash        hash of plaintext (using SHA-256)
   * @return byte[] encryptedHash   the digital signature (usign RSA, ECB with PKCS1Padding)
   */
  public byte[] encryptHash (byte[] hash) {
    System.out.println("\n\tSIGNING HASH WITH SENDER'S PRIVATE KEY:");

    System.out.println("\t\tEncrypting Hash with Private Key");
    //sign hash with private key
    byte[] encryptedHash = null;
    try {
      Cipher RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      RSAcipher.init(Cipher.ENCRYPT_MODE, KRC);
      encryptedHash = RSAcipher.doFinal(hash);

      System.out.println("\t\tEncrypted Hash Size: " + encryptedHash.length);

      System.out.println("\t\tEncrypted Hash: [" + new String (encryptedHash)+"]");


    }
    catch (Exception e) {
      System.err.println(e);
    }
    return encryptedHash;
  }

    /**
   * Concatentates the digital signature to the plaintext (for authentication)
   * @param byte[] encryptedHash  the digital signature (usign RSA, ECB with PKCS1Padding)
   * @param String plaintext    the plaintext to be Encrypted
   * @return  byte[] authMessage    the concatentated payload to be encrypted for confidentiality
   */
  public byte[] authenticatePlaintext (byte[] encryptedHash, String plaintext) {
    System.out.println("\n\tCONCATENATING SIGNATURE AND MESSAGE:");
    byte[] authMessage = null;
    try {
      //concantenate hash and original message

      ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
      //add signature
      outputStream.write(encryptedHash);
      //add message
      outputStream.write(plaintext.getBytes("UTF-8"));
      //concat
      authMessage = outputStream.toByteArray();
      outputStream.close();

      System.out.println("\t\tAuthenticated Packet Size: " + authMessage.length);

      System.out.println("\t\tAuthenticated Packet: [" + new String(authMessage) + "]");
    }
    catch (Exception e) {
      System.err.println(e);
    }
    return authMessage;
  }


  /**
   * Compresses the payload for encryption
   * @param byte[] authMessage  the payload to be encrypted (Digital Signature + Plaintext)
   * @return  byte[] compMessage  the compressed payload to be encrypted
   */

  public byte[] compressMessage (byte[] authMessage) {
    System.out.println("\n\tCOMPRESSING AUTHENTICATED PACKET:");
    byte[] compMessage = null;
    try {

      //zip the above

      //using chunks of 1024 bytes
      byte[] output = new byte[1024];
      //create defalter
      Deflater compress = new Deflater();
      compress.setInput(authMessage);
      //use byte array to avoid running out of space
      ByteArrayOutputStream o = new ByteArrayOutputStream(authMessage.length);
      compress.finish();

      //create zip
      while(!compress.finished()){
        int count = compress.deflate(output);
        o.write(output,0,count);
      }
      o.close();
      compress.end();

      //zipped message
      compMessage = o.toByteArray();

      System.out.println("\t\tCompressed Packet Size: " + compMessage.length);

      System.out.println("\t\tCompressed Packet: [" + new String(compMessage) + "]");


      System.out.println("\n_AUTHENTICATION COMPLETE_");
    }
    catch (Exception e) {
      System.err.println(e);
    }
    return compMessage;
  }

    /**
   * Generates the secret/shared key Ks to be used by the receiver client to decrypt the payload
   */
  public void generateSecretKey () {
    try {
      System.out.println("\n\n_SETTING UP CONFIDENTIALITY_");

      //create shared key
      System.out.println("\n\tCREATING SHARED KEY:");
      KeyGenerator secretKeyGen = KeyGenerator.getInstance("AES");
          secretKeyGen.init(128);
      //GET KEY
          secretKey = secretKeyGen.generateKey();
      //new key spec
      k = new SecretKeySpec(secretKey.getEncoded(), "AES");

      System.out.println("\t\tShared Key Size: " + secretKey.getEncoded().length);

      System.out.println("\t\tShared Key: [ " +  new String(secretKey.getEncoded()) +"]");

    }
    catch (Exception e) {
      System.err.println(e);
    }
  }

    /**
   * Encrypt the compressed payload
   * @param byte[] compMessage  the compressed payload to be encrypted
   * @return  byte[] ciphertext E_(Ks){Z(DS + P)}
   */
  public byte[] generateCiphertext (byte[] compMessage) {
    System.out.println("\n\tENCRYPTING COMPRESSED PACKET WITH SHARED KEY:");
    //create cipher for encryption and encrypt zip

    byte[] ciphertext = null;
    try {
      aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      aescipher.init(Cipher.ENCRYPT_MODE, k);
      ciphertext = aescipher.doFinal(compMessage);

      System.out.println("\t\tEncrypted Compressed Packet Size: " + ciphertext.length);

      System.out.println("\t\tEncrypted Compressed Packet: [" + new String(ciphertext) +"]");

    }
    catch (Exception e) {
      System.err.println(e);
    }

    return ciphertext;
  }

    /**
   * Generates the initiation vector for CBC mode encryption and stores it for receiver to use when decrypting the compressed payload (DS + P)
   */
  public void generateIV () {
    try {
      System.out.println("\t\tExtracting the IV for decryption");

      //get iv from cipher
      byte[] iv = aescipher.getIV();

      System.out.println("\t\tIV size: " + iv.length);

      System.out.println("\t\tIV: [" + new String(iv) +"]");

      //write iv to a file
      System.out.println("\t\tWriting IV to file \"sender_iv.txt\"");
      FileOutputStream fos2 = new FileOutputStream("sender_iv.txt");
      fos2.write(iv);
      fos2.close();
    }
    catch (Exception e) {
      System.err.println(e);
    }
  }

    /**
   * Acquire the receiver's public key KUS
   */
  public void getKUS () {
    System.out.println("\n\tENCRYPTING SHARED KEY WITH RECEIVER'S PUBLIC KEY:");
    try {
      // get receiver public key from file
      System.out.println("\t\tReading in receiver's public key from file \"receiver_public_key.txt\"");
      Path path = Paths.get("receiver_public_key.txt");
      byte[] SKey = Files.readAllBytes(path);

      //create receiver key from bytes
      KUS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(SKey));
    }
    catch (Exception e) {
      System.err.println(e);
    }
  }

    /**
   * Encrypts the shared/secret key Ks
   * @return byte[] encryptedKey  E_(KUS){Ks}
   */
  public byte[] encryptSecretKey () {
    
    System.out.println("\t\tEncrypting shared key with Receiver's Public Key");
    //encrypt shared key with public key of receiver
    byte[] encryptedKey = null;
    try {
      Cipher packet = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      packet.init(Cipher.ENCRYPT_MODE, KUS);
      encryptedKey = packet.doFinal(secretKey.getEncoded());

      System.out.println("\t\tEncrypted Shared Key Size: " + encryptedKey.length);

      System.out.println("\t\tEncrypted Shared Key: [" + new String(encryptedKey) +"]");

    }
    catch (Exception e) {
      System.err.println(e);
    }
    return encryptedKey;
  }

    /**
   *Concatenates the encrypted shared/secret key with the compressed and encrypted digital signature and plaintext
   *@param  byte[] encryptedKey  E_(KUS){Ks}
   *@param  byte[] ciphertext    encrypted + compressed payload E_(Ks){Z(DS + P)}
   *@return byte[] finCiphertext the message to be sent to the receiver
   */
  public byte[] generateFinalCiphertext (byte[] encryptedKey, byte[] ciphertext) {
    System.out.println("\n\tCONCATENATING ENCRYPTED SHARED KEY AND ENCRYPTED PACKAGE:");
    byte[] finCiphertext = null;
    try {

      //concat the encrypyted shared key and the encrypted zip

      ByteArrayOutputStream finalMessage = new ByteArrayOutputStream( );
      finalMessage.write(encryptedKey);
      finalMessage.write(ciphertext);
      finCiphertext = finalMessage.toByteArray();
      finalMessage.close();

      System.out.println("\t\tEncrypted Packet Size: " + finCiphertext.length);

      System.out.println("\t\tEncrypted Packet: [" + new String(finCiphertext) +"]");
      System.out.println("\n_CONFIDENTIALITY COMPLETE_");
    }
    catch (Exception e) {
      System.err.println(e);
    }

    return finCiphertext;
  }

  public byte[] getFinalCipherText () {
    return finCiphertext;
  }

}


/**
 * Handles the receiving and decryption of messages sent from the sender client
 */
class PGPReceive {
  private PrivateKey KRS;//receiver private key
  private PublicKey KUS;//receiver public key
  private PublicKey KUC;//sender public key
  private SecretKey secretKey = null;
  private SecretKeySpec sk = null;

  //Constructor that generates keys and certificate of receiver client
  public PGPReceive(String username){
      generateKeys();
      generateCertificate(username);
  }

  /**
   * Generates the receiver's public/private key pair (KRS, KUS)
   */
  public void generateKeys() {
    try {
      KRS = null; //private key
      //create receiver's assymmetric keys
      System.out.println("\nCREATING RECEIVER PRIVATE AND PUBLIC KEY PAIR:");
      KeyPairGenerator keyGen2 = KeyPairGenerator.getInstance("RSA");
      keyGen2.initialize(1024);
      KeyPair serverkeys = keyGen2.generateKeyPair();
      //get keys
      KRS = serverkeys.getPrivate();
      KUS = serverkeys.getPublic();

      //Write KUS to textfile receiver_public_key.txt
      byte[] KUSArray = KUS.getEncoded();
      System.out.println("\tWriting receiver's Public Key to file \"receiver_public_key.txt\" \n");
      FileOutputStream fos = new FileOutputStream("receiver_public_key.txt");
      fos.write(KUSArray);
      fos.close();
    }
    catch (Exception e) {
      System.err.println(e);
    }
  }

  /**
   * Gets the encrypted shared key (E_(KUS){Ks})
   * @param byte[] message  the message sent from sender
   * @return  byte[] keyPart  the encrypted shared key
   */
  public byte[] getEncrptedKeyPart(byte[] message) {
    byte[] keyPart = new byte[128];
    try {
      //add provider
      Security.addProvider(new BouncyCastleProvider());
      //do crypto stuff here
      System.out.println("\n\n_UNPACKING PACKET_");

      System.out.println("\n\tSPLITTING UP RECEIVED PACKET:");
      //split up packet

      for(int i = 0; i < 128; i++){
        keyPart[i] = message[i];
      }

      System.out.println("\t\tEncrypted Shared Key Size: " + keyPart.length);
      System.out.println("\t\tEncrypted Shared Key: ["+ new String(keyPart) +"]");
    }
    catch (Exception e) {
      System.err.println(e);
    }

    return keyPart;
  }

  /**
   * Gets the ciphertext E_(Ks){Z(DS + P)} from message
   * @param byte[] message  the message sent from sender
   * @return  byte[] crypPart the encrypted and compressed payload
   */
  public byte[] getEncryptedMessagePart(byte[] message) {
    byte[] crypPart = new byte[message.length-128];
    try {

      //we know the encrypted key is 128bits

      //rest is the encrypted message
      for(int j = 128, k = 0; j < message.length; j++, k++){
        crypPart[k] = message[j];
      }

      System.out.println("\t\tEncrypted Compressed Packet Size: " + crypPart.length);

      System.out.println("\t\tEncrypted Compressed Packet: ["+ new String(crypPart) +"]" );

      System.out.println("\n_PACKET UNPACKED_");
    }
    catch (Exception e) {
      System.err.println(e);
    }
    return crypPart;
  }

  /**
   * Decrypts the shared key using KRS
   * @param byte[] keyPart E_(KUS){Ks} (ensuring confidentiality)
   */
  public void decryptSharedKey (byte[] keyPart) {

    try {
      //CONFIDENTIALITY
      System.out.println("\n\n_ENSURING CONFIDENTIALITY_");
      System.out.println("\n\tDECRYPTING SHARED KEY:");

      //decrypt shared key with the private key of the receiver
      byte[] decryptedKey = null;
      Cipher packet = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      packet.init(Cipher.DECRYPT_MODE, KRS);
      decryptedKey = packet.doFinal(keyPart);

      System.out.println("\t\tShared Key Size: " + decryptedKey.length);

      System.out.println("\t\tShared Key: [" + new String(decryptedKey) + "]" );

      //reconstruct shared key
      secretKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
      sk = new SecretKeySpec(secretKey.getEncoded(), "AES");
      System.out.println("\t\tShared Key constructed");
    }
    catch (Exception e) {
      System.err.println(e);
    }
  }

  /**
   * Decrypts the ciphertext E_(Ks){Z(DS + P)} using Ks (ensuring confidentiality)
   * @param byte[] crypPart     the encrypted and compressed payload
   * @return  byte[] decryptedPackage Z(DS + P)
   */
  public byte[] decryptMessage (byte[] crypPart) {
    byte[] decryptedPackage = null;
    try {
      System.out.println("\n\tDECRYPTING COMPRESSED MESSAGE:");

      //get iv for decryption
      System.out.println("\t\tReading in IV from file \"sender_iv.txt\"");
      Path path2 = Paths.get("sender_iv.txt");
      byte[] iv = Files.readAllBytes(path2);

      System.out.println("\t\tIV Size: " + iv.length);

      System.out.println("\t\tIV: [" + new String(iv) + "]" );

      //we decrypt the packet with the iv and the shared key
      Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      aescipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
      decryptedPackage = aescipher.doFinal(crypPart);

      System.out.println("\t\tCompressed Packet Size: " + decryptedPackage.length);

      System.out.println("\t\tCompressed Packet: [" + new String(decryptedPackage +"]"));

      System.out.println("\n_CONFIDENTIALITY ENSURED_");
    }
    catch (Exception e) {
      System.err.println(e);
    }
    return decryptedPackage;
  }

  /**
   * Decompresses payload
   * @param byte[] decryptedPackage Z(DS + P)
   * @return  byte[] authMessage    DS + P (digital signature + plaintext)
   */
  public byte[] decompressMessage (byte[] decryptedPackage) {
    byte[] result = new byte[1024];
    byte[] authMessage = null;
    try {
      //AUTHENTICAION
      System.out.println("\n\n_ENSURING AUTHENTICITY_");

      System.out.println("\n\tDECOMPRESSING PACKAGE:");

      //create inflater
      Inflater decompresser = new Inflater();
      decompresser.setInput(decryptedPackage, 0, decryptedPackage.length);

      //read out values
      ByteArrayOutputStream o2 = new ByteArrayOutputStream(decryptedPackage.length);
      while(!decompresser.finished()){
        int count = decompresser.inflate(result);
        o2.write(result,0,count);
      }
      o2.close();
      authMessage = o2.toByteArray();
      decompresser.end();

      System.out.println("\t\tUncompressed Packet Size: " + authMessage.length);

      System.out.println("\t\tUncompressed Packet: [" + new String(authMessage) +"]");

    }
    catch (Exception e) {
      System.err.println(e);
    }
    return authMessage;
  }

  /**
   * Gets the digital signature DS from the authenticated message (DS + P)
   * @param byte[] authMessage  DS + P (digital signature + plaintext)
   * @return  byte[] sigPart    DS
   */
  public byte[] getSignaturePart (byte[] authMessage) {
    System.out.println("\n\tSPLITTING UNCOMPRESSED MESSAGE:");
    //authMessage is decompressed message
    byte[] sigPart = new byte[128];
    try {
      System.out.println("\t\tSplitting off signature");
      //signature is 128 bytes as we encrypted with private key
      for(int i = 0; i < 128; i++){
        sigPart[i] = authMessage[i];
      }
    }
    catch (Exception e) {
      System.err.println(e);
    }
    return sigPart;
  }

  /**
   * Gets the plaintext P from the authenticated message (DS + P)
   * @param byte[] authMessage  DS + P (digital signature + plaintext)
   * @return  byte[] plaintext  P
   */
  public byte[] getPlaintext (byte[] authMessage) {
    byte[] plaintext = new byte[authMessage.length-128];
    try {
      System.out.println("\t\tSplitting off Plaintext");

      //rest is the plain text
      for(int j = 128, k = 0; j < authMessage.length; j++, k++){
        plaintext[k] = authMessage[j];
      }

      //create message
      System.out.println("\t\tReconstructing Plaintext");
      System.out.println("\t\tPlaintext reads: ");
      System.out.println("\t\t________________________________________________________");
      System.out.println("\t\t" + new String(plaintext) );
      System.out.println("\t\t________________________________________________________");
      System.out.println("\t\tMessage End");

    }
    catch (Exception e) {
      System.err.println(e);
    }
    return plaintext;
  }

  /**
   * genreates the hash of the received plaintext to be compared with the received hash (for authentication)
   * @param byte[] plaintext  original text from client
   * @return  byte[] digest   the hash H_S(P) (using SHA-256)
   */
  public byte[] generatePlaintextHash (byte[] plaintext) {
    byte[] digest = null;
    try {
      System.out.println("\n\tCONFIRMING AUTHENTICITY:");
      //create hash of the message to check signature
      System.out.println("\t\tMaking own Message Digest of Plaintext");

      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(plaintext);
      digest = md.digest();

      System.out.println("\t\tReconstructed Message Digest Size: " + digest.length);

      System.out.println("\t\tReconstructed Message Digest: ["+ new String(digest) +"]" );
    }
    catch (Exception e) {
      System.err.println(e);
    }
    return digest;
  }

  /**
   * acquires the sender's public key to decrypt the digital signature (for authentication)
   */
  public void getKUC () {
    try {
      System.out.println("\t\tReading in sender's public key from \"sender_public_key.txt\"");
      //GET SENDER PUBLIC KEY KUC
      Path path = Paths.get("sender_public_key.txt");
      byte [] CKey = Files.readAllBytes(path);
      //generate public key from bytes
      KUC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(CKey));

      System.out.println("\t\tSender's Public Key Size: " + CKey.length);

      System.out.println("\t\tSender's Public Key: [" + new String(CKey) +"]");
    }
    catch (Exception e) {
      System.err.println(e);
    }
  }

  /**
   * Decrypts the hash
   * @param byte[] sigPart    E_(KRC){H_C(P)}
   * @return byte[] decryptedHash H_C(P) (received from sender)
   */
  public byte[] decryptHash (byte[] sigPart) {
    //decrypt signed hash with public key
    byte[] decryptedHash = null;
    try {
      Cipher hashCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      hashCipher.init(Cipher.DECRYPT_MODE, KUC);
      decryptedHash = hashCipher.doFinal(sigPart);

      System.out.println("\t\tDecrypted Message Digest Size: " + decryptedHash.length);

      System.out.println("\t\tDecrypted Message Digest: [" + new String(decryptedHash) +"]");
    }
    catch (Exception e) {
      System.err.println(e);
    }
    return decryptedHash;
  }

  /**
   * Compares the received and generated hashes and if they are the same then the receiver can verify the authenticity
   * of the digital signature. Thus the receiver knows the message was indeed sent from the sender.
   * @param  byte[] decryptedHash H_C(P) (received from sender)
   * @param  byte[] digest    H_S(P) (generated by receiver)
   */
  public void authenticate (byte[] decryptedHash, byte[] digest) {
    try {
      System.out.println("\t\tChecking if Authenticity was achieved");

      if (Arrays.equals(decryptedHash,digest)){
        System.out.println("\t\tAuthenticity was achieved");
      }else{
        System.out.println("\t\tAuthenticity was not achieved! DONT TRUST THIS MESSAGE!");
      }
      System.out.println("\n_AUTHENTICITY ENSURED_");
    }
    catch (Exception e) {
      System.err.println(e);
    }
  }

  /**
   * Checks authenticity of the sender
   */
  public boolean validateCertificate() 
  {
      boolean auth = false;
      System.out.println("\n_VALIDATING SENDER'S PUBLIC KEY_");

      System.out.println("\t\tReading certificate from file");

      byte[] unsignedCertificate = null;

      //reads senders unsigned certificate from file
      try{
        Path pathUC = Paths.get("sender_certificate.txt");
        unsignedCertificate = Files.readAllBytes(pathUC);
      }
      catch (IOException e) {
        System.err.println(e);
      }

      //reads senders signed certificate from file
      byte[] signedCertificate = null;
      try{
        Path pathSC = Paths.get("signed_certificate.txt");
        signedCertificate = Files.readAllBytes(pathSC);
      }
      catch (IOException e) {
        System.err.println(e);
      }


      PublicKey caPublicKey = null;

      try {
        System.out.println("\t\tReading in CA public key from \"CA_public_key.txt\"");
        //GET CA PUBLIC KEY
        Path pathCA = Paths.get("CA_public_key.txt");
        byte [] CKey = Files.readAllBytes(pathCA);
        //generate public key from bytes
        caPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(CKey));
      }
      catch (Exception e) {
        System.err.println(e);
      }

      System.out.println("\t\tDecrypting Hashed certificate");

      //Decrypt hashed certificate
      byte[] decryptedHash = null;
      try {
        Cipher hashCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        hashCipher.init(Cipher.DECRYPT_MODE, caPublicKey);
        decryptedHash = hashCipher.doFinal(signedCertificate);
      }
      catch (Exception e) {
        System.err.println(e);
      }

      byte[] hash = null;
      System.out.println("\t\tHashing unsigned certificate");
      try {
        //CREATE A HASH OF THE UNSIGNED CERTIFICATE
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(unsignedCertificate);
        hash = md.digest();

      }
      catch (Exception e) {
        System.err.println(e);
      }

      try {
        System.out.println("\t\tChecking Authenticity of sender - comparing");

        if (Arrays.equals(decryptedHash,hash)){
          System.out.println("\t\tAuthenticity was achieved");
          System.out.println("\t\tConnection remains open for communication");
          auth = true;
        }else{
          System.out.println("\t\tAuthenticity was not achieved! DONT TRUST THIS SENDER!");
          System.out.println("\t\tClosing connection");
        }
        System.out.println("\n_AUTHENTICITY ENSURED_");
        }
      catch (Exception e) {
        System.err.println(e);
      }
      return auth;
    }

  /**
  * Generates unsigned certificate for receiver
   */
  public void generateCertificate(String username)
  {
    try {
      System.out.println("\nCREATING RECEIVER CERTIFICATE:");
      //convert username to bytes
      byte[] identityArray = username.getBytes(); 

      //convert receiver public key to bytes
      byte[] KUCArray = KUS.getEncoded();

      System.out.println("\tGenerating certificate (receiver username concatenated with public key)");

      //Concat bytes to form certificate
      byte[] certificate = new byte[identityArray.length + KUCArray.length];
      System.arraycopy(identityArray, 0, certificate, 0, identityArray.length);
      System.arraycopy(KUCArray, 0, certificate, identityArray.length, KUCArray.length);

      System.out.println("\tWriting certificate to file \"receiver_certificate.txt\"\n");

      FileOutputStream fos = new FileOutputStream("receiver_certificate.txt");
      fos.write(certificate);
      fos.close();
  }
      catch (Exception e)
      {
        System.out.println(e);
      }
}

}