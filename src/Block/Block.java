package Block;

import java.io.Serializable;

public class Block implements Serializable {

	private String id;//ID BLOCK
	
	public Block(String id) {
		this.id = id;
	}
	
	/*public Block(String ownerId){
		this.ownerId=ownerId;
	}*/
	
	/*public void addContent(int pos, String content){     
		
		//String s1 = this.content.substring(pos + content.length());
		String s = this.content.substring(0, pos);
		//TODO
		s += content;
		//s += s1;
		this.content = s;
	}*/

	
	public String getId() {
		return id;
	}
	
	public void setId(String id) {
		this.id = id;
	}
}
