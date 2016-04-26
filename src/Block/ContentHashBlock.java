package Block;
import java.io.Serializable;
import java.security.acl.Owner;
import java.util.Arrays;

import HDS.Server;

public class ContentHashBlock extends Block{

	private byte[] content = new byte[Server.BLOCKSIZE];
	private int pos;
	//private String ownerId;
	
	public ContentHashBlock(String id, /*String ownerId,*/ int pos) {
		super(id);
		//this.ownerId = ownerId;
		this.pos = pos;
	}
	
	
	/*public void createWithZeroes() {
		byte[] content = new byte[BlockServer.BLOCKSIZE];
		Arrays.fill(content, (byte)0);
	}

	public String getOwnerId() {
		return ownerId;
	}


	public void setOwnerId(String ownerId) {
		this.ownerId = ownerId;
	}*/


	public void setBlockId(String string) {
		setId(string);
	}
	

	public void setContent(byte[] content) {
		this.content = content;
	}
	
	/*public void addContent(int pos, byte[] newcontent){     

		//slice from index 0 to index pos-1
		byte[] part1 = Arrays.copyOfRange(this.content, 0, pos);
		byte[] part2 = Arrays.copyOfRange(this.content, pos+newcontent.length, this.content.length);
		
//		System.arraycopy(a, 0, c, 0, a.length);
//		System.arraycopy(b, 0, c, a.length, b.length);
//		
//		byte[] finalArray = part1+newcontent+parte2;
//		s += content;
		//s += s1;
		//this.content = s;
	}*/

	public byte[] getContent() {
		return content;
	}

	public int getPos() {
		return pos;
	}
	
	public void setPos(int pos) {
		this.pos = pos;
	}


	public void createWithZeroes() {
		content = new byte[500];
		Arrays.fill(content, (byte)0);
		
	}


	public void writeContent(byte[] content, int initialPosBlock) {
		if(initialPosBlock == 0){
			byte[] part2 = Arrays.copyOfRange(this.content, initialPosBlock + content.length, this.content.length);
			byte[] finalContent = new byte[500];
			System.arraycopy(content, 0, finalContent, 0, content.length);
			System.arraycopy(part2, 0, finalContent, content.length, part2.length);
			this.content = finalContent;
		}
		else{
			byte[] part1 = Arrays.copyOfRange(this.content, 0, initialPosBlock);
			byte[] part3 = Arrays.copyOfRange(this.content, initialPosBlock + content.length, this.content.length);
			byte[] finalContent = new byte[500];
			System.arraycopy(part1, 0, finalContent, 0, part1.length);
			System.arraycopy(content, 0, finalContent, part1.length, content.length);
			System.arraycopy(part3, 0, finalContent, part1.length + content.length, part3.length);
			this.content = finalContent;
		}
	}

}