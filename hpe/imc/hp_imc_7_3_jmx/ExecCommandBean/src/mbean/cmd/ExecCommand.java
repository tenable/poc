package mbean.cmd;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ExecCommand implements ExecCommandMBean {
	
	private String cmd;
	
	public ExecCommand(String cmd) {
		this.cmd = cmd;
	}
	
	public ExecCommand() {
		this.cmd = "whoami";
	}
	
	public String getCmd() {
		return this.cmd;
	}
	
	public void setCmd(String cmd) {
		this.cmd = cmd;
	}

	public String exec(String cmd) {
		try {
            Runtime rt = Runtime.getRuntime();
            Process proc = rt.exec(cmd);
            
            BufferedReader in = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            BufferedReader err = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            String output = "";
            String s;
            while ((s = in.readLine()) != null) {
                output += s + "\n";
            }
            while ((s = err.readLine()) != null) {
                output += s + "\n";
            }
 
            proc.waitFor();
            return output;
        } catch (Exception e) {
            return e.toString();
        }
	}
	
	public String exec() {
		return exec(this.cmd);
	}

}
