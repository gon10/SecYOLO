package Message;

public class ReadMessage extends Message {
	
	private static final long serialVersionUID = 9095442153076363727L;
	private String fileId;
	private int pos;
	private int size;
	private int rid;
	private int ts;
	
	public ReadMessage(String fileId, int pos, int size, int rid){
		this.fileId = fileId;
		this.pos = pos;
		this.size = size;
		this.rid = rid;
	}
	
	public int getRid() {
		return rid;
	}
	public String getFileId(){
		return fileId;
	}
	
	public int getPos(){
		return pos;
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public void setFileId(String fileId) {
		this.fileId = fileId;
	}

	public void setPos(int pos) {
		this.pos = pos;
	}
	
	@Override
	public byte[] getBytes() {
		byte[] byteFileId = getFileId().getBytes();
		byte[] bytePos = Integer.toString(getPos()).getBytes();
		byte[] byteSize = Integer.toString(getSize()).getBytes();
		byte[] byteRid = Integer.toString(getRid()).getBytes();
		
		byte[] c = new byte[byteFileId.length + bytePos.length + byteSize.length + byteRid.length];
		
		
		System.arraycopy(byteFileId, 0, c, 0, byteFileId.length);
		System.arraycopy(bytePos, 0, c, byteFileId.length, bytePos.length);
		System.arraycopy(byteSize, 0, c, byteFileId.length + bytePos.length, byteSize.length);
		System.arraycopy(byteRid, 0, c, byteFileId.length + bytePos.length + byteSize.length, byteRid.length);
		
		return c;
	}
	
}
