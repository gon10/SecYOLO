package HDS;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import Block.ContentHashBlock;
import Message.*;

public class Library {
	public final static int F = 1;
	public final static int NUM_SRVS = 3 * F + 1;
	private String id;
	private KeyPair keyPair;
	private Cipher cipher;
	private MessageDigest messageDigest;
	private ArrayList<ContentHashBlock> contentHashBlocks = new ArrayList<>();
	private ArrayList<Connection> connections= new ArrayList<>();
	private ArrayList<Boolean> ackList;
	private ArrayList<ReadResponseMessage> readList;
	private int wts;
	private int rid;

	public Library() throws UnknownHostException, IOException, InterruptedException {
		for (int i = 0; i < NUM_SRVS; i++ ){
			connections.add(new Connection(new Socket("localhost", 8080 + i)));
		}
	}

	public String Fsinit() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException {

		// generate an RSA key
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		keyPair = keyGen.generateKeyPair();

		// get an RSA cipher object and print the provider
		cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		messageDigest = MessageDigest.getInstance("SHA-1");

		byte[] bytesID = generateHash(keyPair.getPublic().toString().getBytes());
		id = printHexBinary(bytesID);
		
		//ByzantineRegularRegister Algorithm
		wts = 0;
		ackList = new ArrayList<>();
		rid = 0;
		readList = new ArrayList<>();
		//
		
		FSInitMessage message = new FSInitMessage(id, keyPair.getPublic());
		
		MacMessage macMessage = new MacMessage(message);

		broadcastMessage(macMessage);

		return id;
	}

	public boolean FsWrite(int pos, byte[] content) throws IOException, InvalidKeyException, IllegalBlockSizeException,
	BadPaddingException, ClassNotFoundException, InterruptedException {

		byte[] actualContent = content;
		int indexFirstBlockToWrite = pos / Server.BLOCKSIZE;
		int actualBlockIndex = indexFirstBlockToWrite;
		int indexLastBlockToWrite = (pos + content.length) / Server.BLOCKSIZE;
		int initialPosFirstBlock = pos % Server.BLOCKSIZE;
		int finalPosLastBlock = (pos + content.length) % Server.BLOCKSIZE;

		int missingBlocksId = 0;
		ContentHashBlock blockToWrite;
		byte[] contentToBlock;
		byte[] blankBlock = new byte[Server.BLOCKSIZE];

		processBlocks(content, actualContent, indexFirstBlockToWrite, actualBlockIndex, indexLastBlockToWrite,
				initialPosFirstBlock, missingBlocksId, blankBlock);

		ArrayList<String> arrayOfHashIds = generateArrayOfHashIds();//OK
		
		
		//ByzantineRegularRegister Algorithm
		wts++;
		ackList.clear();
		byte[] signatureOfArrayIds = signContent(convertArrayListInBytes(arrayOfHashIds));
		byte[] signatureOfWts = signContent(Integer.toString(wts).getBytes());
		
		System.out.println("size of sign->" + signatureOfWts.length);

		WriteMessage message = new WriteMessage(contentHashBlocks, arrayOfHashIds, signatureOfArrayIds, 
				wts, signatureOfWts,keyPair.getPublic());

		MacMessage macMessage = new MacMessage(message);
		
		
		broadcastMessage(macMessage);

		for (Connection c : connections) {
			new Thread(new Runnable() {

				@Override
				public void run() {
					FileCorruptMessage m;
					try {
						m = (FileCorruptMessage) c.getOis().readObject();

						if (m.isCorrupted()) {
							synchronized (ackList) {
								ackList.add(false);
								ackList.notify();
							}
							//addWriteResponseToArray(false);
						} else {
							// Verifica se a 2ª mensagem que verifica mesmo os HashBlocks está
							// corrupta
							FileCorruptMessage hashBlockCorruptMessage;

							hashBlockCorruptMessage = (FileCorruptMessage) c.getOis().readObject();

							if (!hashBlockCorruptMessage.isCorrupted())
								synchronized (ackList) {
									ackList.add(true);
									ackList.notify();
								}
								//addWriteResponseToArray(true);
							else{
								synchronized (ackList) {
									ackList.add(false);
									ackList.notify();
								}
								//addWriteResponseToArray(false);
							}
						}
						/*synchronized (ackList) {
							ackList.notify();
						}*/
					} catch (ClassNotFoundException | IOException e1) {
						e1.printStackTrace();
					}
				}
			}).start();

		}

		synchronized (ackList) {
			while(ackList.size() <= ((NUM_SRVS + F) / 2)){
				ackList.wait();
			}
		}
		return getFinalResponseToWrite();
	}

	private void processBlocks(byte[] content, byte[] actualContent, int indexFirstBlockToWrite, int actualBlockIndex,
			int indexLastBlockToWrite, int initialPosFirstBlock, int missingBlocksId, byte[] blankBlock) {
		ContentHashBlock blockToWrite;
		byte[] contentToBlock;
		while(missingBlocksId < indexFirstBlockToWrite){
			try{
				contentHashBlocks.get(missingBlocksId);
			}catch(IndexOutOfBoundsException e){
				blockToWrite = new ContentHashBlock(printHexBinary(generateHash(blankBlock)), 0);
				contentHashBlocks.add(missingBlocksId, blockToWrite);
			}
			missingBlocksId++;
		}

		while(actualBlockIndex <= indexLastBlockToWrite){
			try{
				blockToWrite = contentHashBlocks.get(actualBlockIndex);
			}catch(IndexOutOfBoundsException e){
				blockToWrite = new ContentHashBlock(printHexBinary(generateHash(content)), 0);
				contentHashBlocks.add(actualBlockIndex,blockToWrite);
			}
			if(actualBlockIndex == indexFirstBlockToWrite){
				if(actualContent.length + initialPosFirstBlock > Server.BLOCKSIZE){
					contentToBlock = Arrays.copyOfRange(actualContent, 0, Server.BLOCKSIZE - initialPosFirstBlock);
					blockToWrite.writeContent(contentToBlock, initialPosFirstBlock);
					blockToWrite.setBlockId(printHexBinary(generateHash(blockToWrite.getContent())));
					actualContent = Arrays.copyOfRange(actualContent, contentToBlock.length, actualContent.length);
				}
				else{
					contentToBlock = actualContent;
					blockToWrite.writeContent(contentToBlock, initialPosFirstBlock);
					blockToWrite.setBlockId(printHexBinary(generateHash(blockToWrite.getContent())));
				}

			}
			else if(actualBlockIndex == indexLastBlockToWrite){
				blockToWrite.writeContent(actualContent, 0);
				blockToWrite.setBlockId(printHexBinary(generateHash(blockToWrite.getContent())));
			}
			else{
				contentToBlock = Arrays.copyOfRange(actualContent, 0, Server.BLOCKSIZE);
				blockToWrite.writeContent(contentToBlock, 0);
				blockToWrite.setBlockId(printHexBinary(generateHash(blockToWrite.getContent())));
				actualContent = Arrays.copyOfRange(actualContent, contentToBlock.length, actualContent.length);
			}

			actualBlockIndex++;
		}
	}

	private synchronized void addWriteResponseToArray(boolean b){
		ackList.add(b);
	}
	
	private boolean getFinalResponseToWrite(){
		int trues = 0;
		int falses = 0;
		synchronized (ackList) {
			for (boolean b: ackList) {
				if (b) trues++;
				else falses++;
			}
		}
		
		if(trues > falses) return true;
		else return false;	
	}

	private void broadcastMessage(Message message) throws IOException {
		for(Connection c : connections){
			c.getOos().writeObject(message);
			c.getOos().flush();
			c.getOos().reset();
		}
	}

	private byte[] signContent(byte[] content)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		return cipher.doFinal(generateHash(content));
	}

	private byte[] generateHash(byte[] b) {
		messageDigest.update(b);
		return messageDigest.digest();
	}

	private byte[] convertArrayListInBytes(ArrayList<String> arrayList) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);
		for (String element : arrayList) {
			out.writeUTF(element);
		}
		return baos.toByteArray();
	}

	public ArrayList<String> generateArrayOfHashIds() {
		ArrayList<String> arrayOfHashIds = new ArrayList<>();
		for (int i = 0; i < contentHashBlocks.size(); i++) {
			arrayOfHashIds.add(contentHashBlocks.get(i).getId());
		}
		return arrayOfHashIds;
	}
	
	public int FsRead(String id, int pos, int size) throws IOException, ClassNotFoundException, InterruptedException {
		
		
		//ByzantineRegularRegister Algorithm
		rid++;
		readList.clear();
		ReadMessage message = new ReadMessage(id, pos, size, rid);
		
		MacMessage macMessage = new MacMessage(message);
		
		broadcastMessage(macMessage);
		
		for (Connection c : connections) {
			new Thread(new Runnable() {

				@Override
				public void run() {
					FileCorruptMessage m;
					try {
						m = (FileCorruptMessage) c.getOis().readObject();

						if (m.isCorrupted()) {
							if(m.isCorrupted()){
								System.out.println("FILE IS CORRUPTED");
							}
						} 
						
						ReadResponseMessage readResponse = (ReadResponseMessage) c.getOis().readObject();						
						/*byte[] originalWts = decipherSignature(readResponse.getSignatureOfTs(), keyPair.getPublic());
						byte[] wtsInClear = generateHash(Integer.toString(readResponse.getTs()).getBytes());
						System.out.println("cibas " + Arrays.equals(originalWts, wtsInClear));*/
						if(readResponse.getRid() == rid /*&& 
								Arrays.equals(readResponse.getSignatureOfTs(),signContent(Integer.toString(readResponse.getTs()).getBytes()))*/){
							
							
							//----------------ASSINATURA DO FICHEIRO E DO TS NAO SAO VERIFICADAS--------------------------
							
							
							synchronized (readList) {
								readList.add(readResponse);
								readList.notify();
							}
						}
						//FAZER VERIFICACAO DAS ASSINATURAS
						//ADD TO READLIST SE ASSINATURAS ESTIVEREM OK
						
						
						
					} catch (ClassNotFoundException | IOException e1) {
						e1.printStackTrace();
					}
				}
			}).start();

		}
		System.out.println("ANTES DO WHILE");
		synchronized (readList) {
			while(readList.size() <= ((NUM_SRVS + F) / 2)){
				readList.wait();
			}
		}
		System.out.println("DEPOIS DO WHILE");
		
		
		return getFinalReadResponse();
	}
	
	
	private int getFinalReadResponse(){
		
		int finalResponseTs = readList.get(0).getTs();
		int indexFinalResponse = 0;
		
		synchronized (readList) {
			for (int i = 1; i < readList.size(); i++){
				if(finalResponseTs < readList.get(i).getTs()){
					finalResponseTs = readList.get(i).getTs();
					indexFinalResponse = i;
				}
			}
			return readList.get(indexFinalResponse).getContent().length;
		}
	}
	private byte[] decipherSignature(byte[] signature, PublicKey publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		//System.out.println("size->" + signature.length);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(signature);
	}
}
