package HDS;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class ServerLauncher {
	public final static int F = 1;
	public final static int NUM_SRVS = 3 * F + 1;
	public final static int initial_port = 8080;
	public static int i = 0;
	
	public static void main(String[] args) throws InterruptedException {
		for (i = 0; i < NUM_SRVS; i++) {
			new Thread(new Runnable() {
				@Override
				public void run() {
					Server s1 = new Server();
					try {
						s1.runServer(initial_port + i);
					} catch (NoSuchAlgorithmException | IOException e) {
						e.printStackTrace();
					}	
				}
			}).start();
			Thread.sleep(10);
		}
	}
}
