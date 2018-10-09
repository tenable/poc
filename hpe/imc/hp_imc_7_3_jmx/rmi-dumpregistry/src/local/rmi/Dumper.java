package local.rmi;

import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Dumper {
	public static String dump(String ip, int port) {
		String dump = "";
		try {
			Registry registry = LocateRegistry.getRegistry(ip, port);
			String[] boundNames = registry.list();
			
			for (String name : boundNames)
	         {
	            Remote r = registry.lookup(name);  
	            dump += r.toString();
	         }
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (NotBoundException e) {
			e.printStackTrace();
		}
		return dump;
	}
	
	public static ArrayList<HashMap<String, Integer>> parseEndpoints(String ip, int port) {
		String dump = dump(ip, port);
		
		ArrayList<HashMap<String, Integer>> endpoints = new ArrayList<HashMap<String, Integer>>();
		
		String pattern = ".*\\[([0-9.]+):([0-9]+),.*";
		Pattern r = Pattern.compile(pattern);
		
		Matcher m = r.matcher(dump);
		
		if (m.find()) {
			System.out.println("Found ip: " + m.group(1));
			System.out.println("Found port: " + m.group(2));
			
			HashMap<String, Integer> cur = new HashMap<String, Integer>();
			cur.put(m.group(1), Integer.parseInt(m.group(2)));
			endpoints.add(cur);
		}
		
		return endpoints;
		
	}
}
