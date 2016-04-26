package HDS;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;

import Block.ContentHashBlock;
import Block.PublicKeyBlock;
import Message.Message;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class Server {

	private int myPort;
	public final static String HOSTNAME = "localhost";
	public static final int BLOCKSIZE = 500;
	private HashMap<String, PublicKeyBlock> publicKeyBlockId_block = new HashMap<>();
	private HashMap<String, ContentHashBlock> contentHashBlockId_block = new HashMap<>();
	private MessageDigest messageDigest;
	//TODO lock no hashmap
	/*public static void main(String[] args) throws IOException, NoSuchAlgorithmException{
		new Server().runServer();
	}*/
	
	
	public void addBlockToMap(PublicKeyBlock file){
		publicKeyBlockId_block.put(file.getId(), file);
		
	}
	public HashMap<String, PublicKeyBlock> getPublicKeyBlockId_block() {
		return publicKeyBlockId_block;
	}
	/*
	public HashMap<String, Block> getId_File() {
		return id_File;
	}
	*/
	public void runServer(int port) throws IOException, NoSuchAlgorithmException{
		myPort = port;
		messageDigest = MessageDigest.getInstance("SHA-1");
		ServerSocket serverSocket = new ServerSocket(port);
		System.out.println("Server Running on Port " + port);
		ServerThread bt;
		while(true){
			Socket socket = serverSocket.accept();
			System.out.println(port + ": New Client");
			bt = new ServerThread(socket, this);
			bt.start();
		}
	}

	public int getMyPort() {
		return myPort;
	}
	public void put_h(ContentHashBlock contentHashBlock) {
		contentHashBlockId_block.put(contentHashBlock.getId(), contentHashBlock);
	}
	
	public void put_k(ArrayList<String> idHashBlocks, byte[] signatureOfHashIds, int ts, byte[] signatureOfTs , PublicKey publicKey) {
		PublicKeyBlock pubBlock = publicKeyBlockId_block.get(printHexBinary(generateHash(publicKey.toString().getBytes())));
		pubBlock.setContentFiles(idHashBlocks);
		pubBlock.setSignatureOfHashIds(signatureOfHashIds);
		pubBlock.setTs(ts);
		pubBlock.setSignatureOfTs(signatureOfTs);
		
		
	}

	public HashMap<String, ContentHashBlock> getContentHashBlockId_block() {
		return contentHashBlockId_block;
	}
	
	private byte[] generateHash(byte[] b) {
		messageDigest.update(b);
		return messageDigest.digest();
	}

	public PublicKeyBlock getPublicKeyBlockById(String idToRead) {
		
		//This argument id is the id of the owner Hash(PublicKeyClient)
		
		return publicKeyBlockId_block.get(idToRead);
		
		
		
	}

	
}