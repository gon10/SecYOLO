package HDS;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Client {

	private Library library;
	private String myID;

	public Client() throws UnknownHostException, IOException, InterruptedException{
		library = new Library();
	}

	public void FSInit() throws NoSuchAlgorithmException, NoSuchPaddingException, IOException{
		myID = library.Fsinit();
	}
	/*
	public void FSWrite(int pos, byte[] bytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, IOException{
		library.FsWrite(pos, bytes);
	}

	public int FSRead(String id, int pos, int size) throws ClassNotFoundException, IOException{
		return library.FsRead(id, pos, size);
	}*/
	
	public String getID() {
		return myID;
	}




	public static void main(String[] args) throws UnknownHostException, IOException, InterruptedException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

		String myID = null;	
		Library library = new Library();
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
		String optionChosen;
		Boolean exit = false;
		System.out.println("Options:\n1 - FSinit\n2 - Write\n3 - Read\n");
		while(!exit){

			optionChosen = bufferedReader.readLine();

			switch (optionChosen) {

			case "exit":
				exit = true;
				break;			

			case "help":
				System.out.println("Options:\n1 - FSinit\n2 - Write\n3 - Read\n");
				break;

			case "1":				 
				myID = library.Fsinit();
				System.out.println("System initiated, your ID is: ["+myID+"]");
				break;

			case "2":
				System.out.print("Insert the position: ");
				String s = bufferedReader.readLine();
				int pos = Integer.parseInt(s);
				System.out.print("Write something: ");
				String content = bufferedReader.readLine();
				if(!library.FsWrite(pos, content.getBytes())){
					System.out.println("FILE CORRUPTED, TRY AGAIN");
				}
				else{
					System.out.println("WRITE SUCCESSFUL");
				}
				break;
				
			case "3":
				System.out.print("Type the owner of the file: ");
				String fileId = bufferedReader.readLine();
				System.out.print("Insert the position: ");
				String positionString = bufferedReader.readLine();
				int position = Integer.parseInt(positionString);
				System.out.print("Insert the size of the content you want to read: ");
				String sizeString = bufferedReader.readLine();
				int size = Integer.parseInt(sizeString);
				int bytes = library.FsRead(fileId, position, size);
				//				System.out.println(Arrays.toString(library.FsRead(fileId, position, size)));
				//				System.out.println(new String(bytes, "UTF-8"));
				System.out.println("Bytes read: " + bytes);
				break;

			default:
				break;
			}
		}
	}

}

