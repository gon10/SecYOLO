package Message;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.ArrayList;

import Block.ContentHashBlock;

public class WriteMessage extends Message {
	
	
	private ArrayList<ContentHashBlock> blocks;
	private ArrayList<String> arrayOfHashIds;
	private byte[] signatureOfArrayIds;
	private int wts;
	private byte[] signatureOfWts;
	private PublicKey publicKey;
	
	public int getWts() {
		return wts;
	}


	public void setWts(int wts) {
		this.wts = wts;
	}


	public byte[] getSignatureOfWts() {
		return signatureOfWts;
	}


	public void setSignatureOfWts(byte[] signatureOfWts) {
		this.signatureOfWts = signatureOfWts;
	}




	public WriteMessage(ArrayList<ContentHashBlock> blocks, ArrayList<String> arrayOfHashIds,
			byte[] signatureOfArrayIds, int wts, byte[] signatureOfWts, PublicKey publicKey) {
		super();
		this.blocks = blocks;
		this.arrayOfHashIds = arrayOfHashIds;
		this.signatureOfArrayIds = signatureOfArrayIds;
		this.wts = wts;
		this.signatureOfWts = signatureOfWts;
		this.publicKey = publicKey;
	}


	public ArrayList<ContentHashBlock> getBlocks() {
		return blocks;
	}


	public void setBlocks(ArrayList<ContentHashBlock> blocks) {
		this.blocks = blocks;
	}


	public byte[] getSignatureOfArrayIds() {
		return signatureOfArrayIds;
	}


	public void setSignatureOfArrayIds(byte[] signatureOfArrayIds) {
		this.signatureOfArrayIds = signatureOfArrayIds;
	}


	public ArrayList<String> getArrayOfHashIds() {
		return arrayOfHashIds;
	}


	public void setArrayOfHashIds(ArrayList<String> arrayOfHashIds) {
		this.arrayOfHashIds = arrayOfHashIds;
	}


	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}


	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	
	@Override
	public byte[] getBytes() {
		
		byte[] bytesBlocks = null;
		byte[] bytesArrayOfHashIds = null;
		try {
			bytesBlocks = convertArrayListObjectInBytes(getBlocks());
			bytesArrayOfHashIds = convertArrayListStringInBytes(getArrayOfHashIds());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] byteSignatureOfArrayIds = signatureOfArrayIds;
		byte[] byteWts = Integer.toString(getWts()).getBytes();
		byte[] byteSignatureOfWts = getSignatureOfWts();
		byte[] bytePublicKey = publicKey.toString().getBytes();
		
		byte[] c = new byte[bytesBlocks.length + bytesArrayOfHashIds.length +
		                    byteSignatureOfArrayIds.length + byteWts.length +
		                    byteSignatureOfWts.length + bytePublicKey.length];
		
		
		System.arraycopy(bytesBlocks, 0, c, 0, bytesBlocks.length);
		System.arraycopy(bytesArrayOfHashIds, 0, c, bytesBlocks.length, bytesArrayOfHashIds.length);
		System.arraycopy(byteSignatureOfArrayIds, 0, c, bytesBlocks.length + bytesArrayOfHashIds.length, byteSignatureOfArrayIds.length);
		System.arraycopy(byteWts, 0, c, bytesBlocks.length + bytesArrayOfHashIds.length + byteSignatureOfArrayIds.length, byteWts.length);
		System.arraycopy(byteSignatureOfWts, 0, c, bytesBlocks.length + bytesArrayOfHashIds.length + byteSignatureOfArrayIds.length + byteWts.length, byteSignatureOfWts.length);
		System.arraycopy(bytePublicKey, 0, c, bytesBlocks.length + bytesArrayOfHashIds.length + byteSignatureOfArrayIds.length + byteWts.length + byteSignatureOfWts.length, bytePublicKey.length);
		
		return c;
		
	}
	
	private byte[] convertArrayListObjectInBytes(ArrayList<ContentHashBlock> arrayList) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);
		ObjectOutputStream out1 = new ObjectOutputStream(baos); 
		for (ContentHashBlock element : arrayList) {
			out1.writeObject(element);
		}
		return baos.toByteArray();
	}
	
	private byte[] convertArrayListStringInBytes(ArrayList<String> arrayList) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);
		for (String element : arrayList) {
			out.writeUTF(element);
		}
		return baos.toByteArray();
	}
}
