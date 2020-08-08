import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.net.BindException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.ArrayList;
import java.util.UUID;
import java.net.SocketAddress;
import java.net.SocketException;
import java.lang.Integer;
import java.io.DataInputStream;
import java.io.PrintStream;
import java.io.InputStreamReader;
import javax.crypto.*;//for crypto
import java.security.*;//for crypto
import java.security.spec.*;
import javax.crypto.spec.*;

/**
   * Group members:
   * Justin Dorman: DRMJUS001
   * Zachary Bresler: BRSZAC002
   * Chad Piha: PHXCHA001
   * Emil Kenguerli: KNGEMI001
*/
public class ChatServer {

  private static ServerSocket serverSocket;
  private static int portNumber = 60123;
  private static ConcurrentHashMap<UUID,ServiceConnection> connections = new ConcurrentHashMap<UUID,ServiceConnection>();
  private static ConcurrentHashMap<UUID,ChatGroup> groups = new ConcurrentHashMap<UUID,ChatGroup>();


  public static void main(String args[]){
    generateCAKeys(); //creates CA public and private key pair
    initialiseServerSocket();
    acceptClients();
  }


  public static void initialiseServerSocket(){
    try{
      serverSocket = new ServerSocket(portNumber);
    }catch(IOException e){
      System.out.println(e);
    }
  }

  //accepts client connections
  public static void acceptClients(){
    while(true){
      try{
        Socket serviceSocket = serverSocket.accept();
        UUID clientId = UUID.randomUUID();
        ServiceConnection connection = new ServiceConnection(clientId, serviceSocket);
        connection.start();
        connections.put(clientId, connection);
      }catch(IOException e){
        System.out.println(e);
      }
    }
  }

  //Generates the public and private key pair for the CA
  public static void generateCAKeys()
  {
    try {
      //create private and public keys for CA
      System.out.println("\nCREATING CA PRIVATE AND PUBLIC KEY PAIR:");
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(2048);
      KeyPair keys = keyGen.generateKeyPair();

      //get the key from the generator
      PrivateKey caPrivate = keys.getPrivate();
      PublicKey caPublic = keys.getPublic();

      //convert to bytes
      byte[] privateKeyArray = caPrivate.getEncoded();
      byte[] publicKeyArray = caPublic.getEncoded();
      

      //write out the public key to a file
      System.out.println("\n\tWriting Public Key to file \"CA_public_key.txt\"");
      FileOutputStream fosPublic = new FileOutputStream("CA_public_key.txt");
      fosPublic.write(publicKeyArray);
      fosPublic.close();

      //write out the private key to a file
      System.out.println("\n\tWriting Private Key to file \"CA_private_key.txt\" \n");
      FileOutputStream fosPrivate = new FileOutputStream("CA_private_key.txt");
      fosPrivate.write(privateKeyArray);
      fosPrivate.close();

    }
    catch (Exception e) {
      System.err.println(e);
    }

  }


  public static ChatGroup addConnectionToNewGroup(String groupName, String password, ServiceConnection connection){
    for(ChatGroup group : groups.values()) {
      if(group.getGroupName().equals(groupName)) {
        return null;
      }
    }
    UUID groupId = UUID.randomUUID();
    ChatGroup searchGroup = new ChatGroup(groupName, password, groupId);
    searchGroup.addConnection(connection);
    groups.put(groupId, searchGroup);
    return searchGroup;
  }


  public static ChatGroup addConnectionToExistingGroup(String groupName, String password, ServiceConnection connection){
    ChatGroup searchGroup = null;
    for(ChatGroup group : groups.values()) {
      if(group.getGroupName().equals(groupName)) {
        if(!password.equals(group.getPassword())){
          return null;
        }else{
          searchGroup = group;
          connection.setGroupId(group.getGroupId());
          searchGroup.addConnection(connection);
          break;
        }
      }
    }
    System.out.println("Correct function call: " + searchGroup);
    return searchGroup;
  }


  public static ChatGroup getGroup(UUID groupId){
    return groups.get(groupId);
  }


  public static ConcurrentHashMap<UUID,ChatGroup> getGroups(){
    return groups;
  }

  public static ConcurrentHashMap<UUID,ServiceConnection> getConnections(){
    return connections;
  }
}

//Controls connections to clients
class ServiceConnection extends Thread {
  private UUID clientId;
  private UUID groupId;
  private Socket serviceSocket;
  private SocketAddress remoteSocketAddress;
  private DataOutputStream out;
  private DataInputStream in;
  private ChatGroup group;


  public ServiceConnection(UUID clientId, Socket serviceSocket){
    this.clientId = clientId;
    this.serviceSocket = serviceSocket;
    this.remoteSocketAddress = serviceSocket.getRemoteSocketAddress();
  }

  public void run(){
    try{
      out = new DataOutputStream(serviceSocket.getOutputStream());
      in = new DataInputStream(new BufferedInputStream(serviceSocket.getInputStream()));
      System.out.println("Just connected to " + remoteSocketAddress);
      while(!serviceSocket.isClosed()){
        String instruction = in.readUTF();
        System.out.println(remoteSocketAddress);
        String groupName;
        String password;
        switch(instruction){
          case "set_group_name --new":
            groupName = in.readUTF();
            password = in.readUTF();
            group = ChatServer.addConnectionToNewGroup(groupName,password, this);
            if(group == null){
              out.writeUTF("false");
            }else{
              out.writeUTF("true");
            }
            break;
          case "set_group_name --existing":
            groupName = in.readUTF();
            password = in.readUTF();
            group = ChatServer.addConnectionToExistingGroup(groupName,password, this);
            if(group == null){
              out.writeUTF("false");
            }else{
              out.writeUTF("true");
            }
            break;
          case "client_out_message --true":
            byte[] message = null;
            int msgLength = in.readInt();
            if (msgLength >0)
            {
              message = new byte[msgLength];
              in.readFully(message, 0, message.length);
            }
            group.sendMessages(message);
            break;
        }
      }
      System.out.println("Connection with " + remoteSocketAddress + " is now closed");
    }catch(IOException e){
      System.out.println(e);
    }
  }

  public void setGroupId(UUID groupId){
    this.groupId = groupId;
  }


  public UUID getGroupId(){
    return groupId;
  }


  public SocketAddress getRemoteSocketAddress(){
    return this.remoteSocketAddress;
  }


  public DataOutputStream getWriter(){
      return out;
  }

  public UUID getClientId(){
    return clientId;
  }

}

//Controls chat rooms
class ChatGroup {

  ConcurrentHashMap<UUID,ServiceConnection> connections = new ConcurrentHashMap<UUID, ServiceConnection>();
  String groupName;
  String password;
  UUID groupId;


  public ChatGroup(String groupName, String password, UUID groupId){
    this.groupName = groupName;
    this.password = password;
    this.groupId = groupId;
  }


  public void addConnection(ServiceConnection connection){
    UUID clientId = connection.getClientId();
    connections.put(clientId, connection);
  }

  public void sendMessages(byte[] message){
    for(ServiceConnection connection: connections.values()){
      try{
        DataOutputStream writer = connection.getWriter();
          writer.writeUTF("client_in_message --true");
          writer.writeInt(message.length);
          writer.write(message);
      }catch(IOException e){
        connections.remove(connection.getClientId());
        System.out.println("Connection with remote socket " + connection.getRemoteSocketAddress() + " has been closed");
      }
    }
  }

  public String getGroupName(){
    return groupName;
  }


  public UUID getGroupId(){
    return groupId;
  }


  public ConcurrentHashMap<UUID,ServiceConnection> getConnections(){
    return connections;
  }


  public String getPassword(){
    return password;
  }


}
