package Block;
import java.awt.List;
import java.security.PublicKey;
import java.util.ArrayList;

public class PublicKeyBlock extends Block{
	
	private PublicKey publicKey;
	private ArrayList<String> contentHashBlockId = new ArrayList();
	private byte[] signatureOfHashIds;
	private int ts;
	private byte[] signatureOfTs;

	public int getTs() {
		return ts;
	}

	public void setTs(int ts) {
		this.ts = ts;
	}

	public PublicKeyBlock (String id, PublicKey publicKey) {
		super(id);
		this.publicKey = publicKey;
		this.ts = 0;
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}

	public ArrayList<String> getContentFiles() {
		return contentHashBlockId;
	}

	public void setContentFiles(ArrayList<String> contentFiles) {
		this.contentHashBlockId = contentFiles;
	}

	public byte[] getSignatureOfHashIds() {
		return signatureOfHashIds;
	}

	public void setSignatureOfHashIds(byte[] signature) {
		this.signatureOfHashIds = signature;
	}

	public byte[] getSignatureOfTs() {
		return signatureOfTs;
	}

	public void setSignatureOfTs(byte[] signatureOfTs) {
		this.signatureOfTs = signatureOfTs;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	
	
}