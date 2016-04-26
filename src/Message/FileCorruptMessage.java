package Message;

public class FileCorruptMessage extends Message{
	private boolean corrupted;
	
	public FileCorruptMessage(boolean b){
		this.corrupted = b;
	}
	
	public boolean isCorrupted(){
		return corrupted;
	}
}
