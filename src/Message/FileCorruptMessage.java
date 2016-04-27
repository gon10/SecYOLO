package Message;

public class FileCorruptMessage extends Message{
	private boolean corrupted;
	private int ts;
	
	public FileCorruptMessage(boolean b){
		this.corrupted = b;
	}
	
	public FileCorruptMessage(boolean b, int wts) {
		this.corrupted = b;
		this.ts = wts;
	}

	public boolean isCorrupted(){
		return corrupted;
	}

	public void setCorrupted(boolean corrupted) {
		this.corrupted = corrupted;
	}

	public int getTs() {
		return ts;
	}

	public void setTs(int ts) {
		this.ts = ts;
	}
	
}
