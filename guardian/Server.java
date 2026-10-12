import java.io.*;
import java.net.*;
public class Server {
 public static void main(String[] args) {
 try {
 // Create server socket on port 5000
 ServerSocket serverSocket = new ServerSocket(5000);
 System.out.println("Server is waiting for connection...");
 // Accept client connection
 Socket socket = serverSocket.accept();
 System.out.println("Client connected.");
 // Read message from client
 BufferedReader in = new BufferedReader(
 new InputStreamReader(socket.getInputStream()));
 String message = in.readLine();
 System.out.println("Message received from client: " + message);
 // Close resources
 in.close();
 socket.close();
 serverSocket.close();
 } catch (IOException e) {
 System.out.println("Error: " + e.getMessage());
 }
 }
}

