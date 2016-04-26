package Message;

import java.security.PublicKey;

public class FSInitMessage extends Message{

	private String id;
	private PublicKey publicKey;
	public FSInitMessage(String id, PublicKey publicKey) {
		this.id = id;
		this.publicKey = publicKey;
	}
	
	public String getId(){
		return id;
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	@Override
	public byte[] getBytes() {
		byte[] bytes = id.getBytes();
		byte[] bytes1 = publicKey.toString().getBytes();
		
		byte[] c = new byte[bytes.length + bytes1.length];
		System.arraycopy(bytes, 0, c, 0, bytes.length);
		System.arraycopy(bytes1, 0, c, bytes.length, bytes1.length);
		
		return c;
		
	}
	
}
