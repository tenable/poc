package tls.cert;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;

import local.rmi.Dumper;

public class Runner {

	private static void printUsage() {
		String usageText = "Usage: \n" +
				"java -jar <DownloadCert.jar> <Target IP> <Target JMX Port> <Java Keystore Path> <Keystore Password>";
		System.out.println(usageText);
	}
	
	public static void main(String[] args) {
		if (args.length < 4) {
			System.err.println("Too few arguments.");
			printUsage();
			System.exit(1);
		}

		String host = args[0];
		int port = 0;
		
		// validate args
		try {
			InetAddress.getByName(host);
			port = Integer.parseInt(args[1]);
		} catch (UnknownHostException e) {
			System.err.println("Invalid IP address.");
			System.exit(1);
		} catch (NumberFormatException e) {
			System.err.println("Invalid port.");
			System.exit(1);
		}
		
		String keystore = args[2];	// path to Java keystore
		File keystore_file = new File(keystore);
		if (!keystore_file.exists()) {
			System.err.println("Invalid keystore file path.");
			System.exit(1);
		}
		
		String pass = args[3];		// keystore password
		
		// dump RMI registry to get other port to query
		System.out.println("Probing RMI endpoints...");
		ArrayList<HashMap<String, Integer>> endpoints = Dumper.parseEndpoints(host, port);
		
		if (endpoints.size() == 0) {
			System.err.println("Unable to parse RMI endpoints. Exiting.");
			System.exit(1);
		}
				
		ArrayList<String> cert_aliases = new ArrayList<String>();
		
		CertManager cert_mgr;
		cert_mgr = new CertManager(pass, keystore);
		
		// Grab SSL certificate on found ip/ports
		// endpoint = {ip:port}
		for (HashMap<String, Integer> endpoint : endpoints) {
			for (String key: endpoint.keySet()) {
				String cur_ip = key;
				int cur_port = endpoint.get(key);
				
				ArrayList<String> ip_addrs = new ArrayList<String>();
				
				// if another ip is listed, look at that and host
				ip_addrs.add(cur_ip);
				if (!cur_ip.equals(host))
					ip_addrs.add(host);
				
				for (String ip : ip_addrs) {
					System.out.println("Attempting to fetch certificate from " + ip + " on port " + cur_port + "...");
					Fetch f = new Fetch(ip, cur_port);
					
					try {
						ArrayList<Certificate> certs = f.getCerts();
						System.out.println("Got " + certs.size() + " certs...");
						
						for (Certificate cert: certs) {
							String alias = "imc" + cert_aliases.size();
							boolean stored = cert_mgr.storeCert(alias, cert);
							if (stored) {
								System.out.println("Stored cert with alias " + alias + "...");
								cert_aliases.add(alias);
							}
						}
					} catch (KeyManagementException e) {
						e.printStackTrace();
					}
				}
			}
		}
		
		if (cert_aliases.size() == 0) {
			System.err.println("Unable to download server certificate. Exiting.");
			System.exit(1);
		}
		
		// write to cert files...
//		for (int i = 0; i < certs.size(); i++) {
//			File file = new File("/Users/clyne/out" + i + ".cer");
//			try {
//				FileOutputStream fos = new FileOutputStream(file);
//				fos.write(certs.get(i).getEncoded());
//				fos.close();
//				
//			} catch (IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			} catch (CertificateEncodingException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		}
		
		
		// now, remove the certs from the keystore (cleanup)
		//			System.out.println("Cleaning up keystore...");
					//for (String alias: cert_aliases) {
					//	boolean deleted = cert_mgr.deleteCert(alias);
					//	if (!deleted) {
					//		System.err.println("Could not delete cert with alias '" + alias + "'");
					//	}
					//}
		
		

	}

}
