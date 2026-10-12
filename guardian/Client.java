import java.net.*;
public class ClientAddressClient {
public static void main(String[] args) {
try {
 Socket socket = new Socket("localhost", 5000);
 System.out.println("Connected to Server");
 socket.close();
 } catch (Exception e) {
 System.out.println(e);
 }
 }