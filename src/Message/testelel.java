package Message;

public class testelel {

	private  Message msg;
	
	public static void main(String[] args) {
		
		
		Message m = new Message();
		Message m1 = new WriteMessage(null, null, null, 0, null, null);
		WriteMessage m2 = new WriteMessage(null, null, null, 0, null, null);
		
		bebas(m2);
		
		m.getBytes();
		m1.getBytes();
		m2.getBytes();
	}
	
	
	public static void bebas(Message msg){
		msg.getBytes();
	}
}
