package Message;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MacMessage extends Message{
	
	
	private Message msg;
	private byte[] mac;
	
	public MacMessage(Message msg) {
		this.msg = msg;
		generateMac();
	}
	
	public void generateMac(){
		
		try {
		     String secret = "secret";
		     
		     byte[] message = msg.getBytes();

		     Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		     SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
		     sha256_HMAC.init(secret_key);

		     mac = sha256_HMAC.doFinal(message);
		    }
		    catch (Exception e){
		     System.out.println("Error");
		    }
		
	}


	public Message getMsg() {
		return msg;
	}


	public void setMsg(Message msg) {
		this.msg = msg;
	}


	public byte[] getMac() {
		return mac;
	}


	public void setMac(byte[] mac) {
		this.mac = mac;
	}
	
	
}
