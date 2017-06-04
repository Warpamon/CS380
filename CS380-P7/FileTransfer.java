import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.*;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

public class FileTransfer{
	static Scanner scann = new Scanner(System.in);
	public static void main(String[] args)throws Exception{
		if(args.length >= 1)
		{
			switch(args[0]){
			case"makekeys":
				generateKey();
				break;
			case"server":
				String privateKey = args[1];
				String portN = args[2];
				server(privateKey, portN);
				break;
			case"client":
				String portNum = args[3];
				String fileName = args[1];
				String host = args[2];
				client(host,portNum,fileName);
				break;
			}
		}
		else
		{
			System.out.println("There wasnt a correct ammount of argument, "
					+ "this program needs atleast of argument to run.\n"
					+ "Your options for running this program are:/n"
					+ "'java FileTransfer makekeys\n"
					+ "'java FileTransfer client' which requires Strings<host><portNum><publicKey>\n"
					+ "'java FileTransfer server' which requires Strings<privateKey><portNum>");
		}
	}
	//if the command line argument is client go into CLIENT MODE
	private static void client(String host, String portNum, String publicKey) throws Exception
	{
		try (Socket socket = new Socket(host, Integer.parseInt(portNum))) {
		System.out.println("Connected to server: " + Integer.parseInt(portNum));
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(publicKey));
		PublicKey pubKey = null;
		pubKey = getPubKey(pubKey, publicKey);
		
		//1. Generate AES session key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		SecureRandom rand = new SecureRandom();
		keyGen.init(128, rand);
		Key sessionKey = keyGen.generateKey();
		Cipher cipher = Cipher.getInstance("RSA");
		
		//2. encrypt session key
		cipher.init(Cipher.WRAP_MODE, pubKey);
		byte[] wrapKey = cipher.wrap(sessionKey);
		
		//3. enter path for file
		System.out.println("Enter the file path: " );
		String filePath = scann.next();
		File file = new File(filePath);
		FileInputStream inFile = null;
		byte[] data = new byte[(int)file.length()];
		inFile = new FileInputStream(file);
		inFile.read(data);
		//4. enter desired chunk size
		System.out.println("Enter chunk size [1024]: ");
		int chunkSize = scann.nextInt();
		int packets = (int) file.length() / chunkSize;
		double value = (double) file.length() / (double) chunkSize;
		if(value > (double) packets){
			packets++;
		}
		//5. send start message to server
		StartMessage start = new StartMessage(filePath, wrapKey, chunkSize);
		OutputStream out = socket.getOutputStream();
		ObjectOutputStream objout = new ObjectOutputStream(out);
		DataOutputStream dos = new DataOutputStream(out);
		objout.writeObject(start);
		cipher = Cipher.getInstance("AES");
		Chunk chunk = null;
		byte[] chunkD = null;
		int spot = 0;
		System.out.print("Sending: " + filePath);
		System.out.println("	File Size: " + file.length());
		System.out.println("Sending " + packets + " chunks.");
		InputStream ins = socket.getInputStream();
		ObjectInputStream objIn = new ObjectInputStream(ins);
		for(int i = 0; i < packets; i++){
			AckMessage ack = (AckMessage) objIn.readObject();
			if(ack.getSeq() == i){
				System.out.println("Chunks completed [ " + ack.getSeq() + "/" + packets + "]");
				if((spot + chunkSize) < file.length()){
					chunkD = new byte[chunkSize];
				}
				else {
					chunkD = new byte[(int) (file.length() - spot)];
				}
				for(int j = 0; j < chunkSize && ((j + spot) < file.length()); j++){
					chunkD[j] = data[j + spot];
				}
				Checksum cs = new CRC32();
				cs.update(chunkD, 0, chunkD.length);
				long crc = cs.getValue();
				cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
				byte[] decodeText = cipher.doFinal(chunkD);
				chunk = new Chunk(i, decodeText, (int) crc);
				objout.writeObject(chunk);
				spot += chunkSize;
			}
			else {
				i--;
				objout.writeObject(chunk);
			}
		}
		DisconnectMessage dis = new DisconnectMessage();
		objout.writeObject(dis);
		}
		
	}
	//if command line argument is server then go into SERVER MODE
	private static void server(String privateKey, String portNum)
	{
		try {
			ServerSocket sock = new ServerSocket(Integer.parseInt(portNum));
			Socket socket = sock.accept();
			String address = socket.getInetAddress().getHostAddress();
			PrivateKey privK = null;
			privK = getPrivKey(privK,privateKey);
			//creating listeners to use depending on whats being sent
			InputStream in = socket.getInputStream();
			ObjectInputStream objIn = new ObjectInputStream(in);
			//read in message
			Object message = objIn.readObject();
			StartMessage start = null;
			
			//2. if start message is sent prepare for file transfer
			if (message instanceof StartMessage)
			{
				start = (StartMessage)message;
			}
			//1. else its disconnect message so disconnect
			else
			{
				socket.close();
			}
			byte[] encryptedKey = start.getEncryptedKey();
			//decript the key that was sent
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.UNWRAP_MODE, privK);
			//turn into an instance of Key
			Key key = cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
			//respond with ack 0 after start message received
			AckMessage ackM = new AckMessage(0);
			OutputStream out = socket.getOutputStream();
			ObjectOutputStream objout = new ObjectOutputStream(out);
			objout.writeObject(ackM);
			cipher = Cipher.getInstance("AES");
			int packets = (int) start.getSize() / start.getChunkSize();
			double value = (double) start.getSize() / (double) start.getChunkSize();
			if(value > (double) packets){
				packets++;
			}
			
			byte[] file = new byte[(int) start.getSize()];
			int pointer = 0;
			for(int i = 0; i < packets; i++){
				Chunk chunk = (Chunk) objIn.readObject();
				if(chunk.getSeq() == 1){
					cipher.init(Cipher.DECRYPT_MODE, key);
					byte[] decode = cipher.doFinal(chunk.getData());
					Checksum cs = new CRC32();
					cs.update(decode, 0, decode.length);
					long crc = cs.getValue();
					if(crc == (long) chunk.getCrc()){
						for(int j = 0; j < decode.length; j++){
							file[j + pointer] = decode[j];
						}
						pointer += decode.length;
						ackM = new AckMessage(i++);
						objout.writeObject(ackM);
						System.out.println("Chunk received [" + chunk.getSeq() + "/" 
								+ packets + "]");
						if(chunk.getSeq() == packets){
							System.out.println("Trasfer complete");
							System.out.print("Output path: ");
							String fileName = scann.next();
							FileOutputStream fout = new FileOutputStream(fileName);
							fout.write(file);
							break;
						}
					}
					else {
						ackM = new AckMessage(i);
						objout.writeObject(ackM);
						i--;
					}
				}
				else {
					ackM = new AckMessage(i);
					objout.writeObject(ackM);
					i--;
				}
			}
			
		} catch (Exception e) { 
			System.out.println("Something went wrong! error!");
			e.printStackTrace();
		}
	}
	//if command is makekeys this genereates a private/public RSA key	
	private static void generateKey() {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(4096); // you can use 2048 for faster key generation
			KeyPair keyPair = gen.genKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream( 
					new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
			} catch (NoSuchAlgorithmException | IOException e) {
				e.printStackTrace(System.err);
			}
	}
	
	private static PublicKey getPubKey(PublicKey pubK, String file) 
			throws IOException, ClassNotFoundException {
		FileInputStream in = new FileInputStream(file);
		ObjectInputStream obin = new ObjectInputStream(in);
		pubK = (PublicKey) obin.readObject();
		return pubK;
	}
	
	private static PrivateKey getPrivKey(PrivateKey priK, String file) 
			throws IOException, ClassNotFoundException{
		FileInputStream in = new FileInputStream(file);
		ObjectInputStream obin = new ObjectInputStream(in);
		priK = (PrivateKey) obin.readObject();
		return priK;
	}
	

}


