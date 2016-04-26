package Message;

public class ReadResponseMessage extends Message {

	private byte[] content;
	private int rid;
	private int ts;
	private byte[] signatureOfHashIds;
	private byte[] signatureOfTs;
	public ReadResponseMessage(byte[] content, int rid, int ts, byte[] signatureOfHashIds, byte[] signatureOfTs) {
		super();
		this.content = content;
		this.rid = rid;
		this.ts = ts;
		this.signatureOfHashIds = signatureOfHashIds;
		this.signatureOfTs = signatureOfTs;
	}
	public byte[] getContent() {
		return content;
	}
	public void setContent(byte[] content) {
		this.content = content;
	}
	public int getRid() {
		return rid;
	}
	public void setRid(int rid) {
		this.rid = rid;
	}
	public int getTs() {
		return ts;
	}
	public void setTs(int ts) {
		this.ts = ts;
	}
	public byte[] getSignatureOfHashIds() {
		return signatureOfHashIds;
	}
	public void setSignatureOfHashIds(byte[] signatureOfHashIds) {
		this.signatureOfHashIds = signatureOfHashIds;
	}
	public byte[] getSignatureOfTs() {
		return signatureOfTs;
	}
	public void setSignatureOfTs(byte[] signatureOfTs) {
		this.signatureOfTs = signatureOfTs;
	}
	
	
	@Override
	public byte[] getBytes() {
		byte[] byteContent = getContent();
		byte[] byteRid = Integer.toString(getRid()).getBytes();
		byte[] byteTs = Integer.toString(getTs()).getBytes();
		byte[] byteSignatureOfHashIds = getSignatureOfHashIds();
		byte[] byteSignatureOfTs = getSignatureOfTs();
		
		byte[] c = new byte[byteContent.length + byteRid.length + byteTs.length + byteSignatureOfHashIds.length + 
		                    byteSignatureOfTs.length];
		
		System.arraycopy(byteContent, 0, c, 0, byteContent.length);
		System.arraycopy(byteRid, 0, c, byteContent.length, byteRid.length);
		System.arraycopy(byteTs, 0, c, byteContent.length + byteRid.length, byteTs.length);
		System.arraycopy(byteSignatureOfHashIds, 0, c, byteContent.length + byteRid.length + byteTs.length, byteSignatureOfHashIds.length);
		System.arraycopy(byteSignatureOfTs, 0, c, byteContent.length + byteRid.length + byteTs.length + byteSignatureOfHashIds.length, byteSignatureOfTs.length);
		
		return c;
	}
	


}
