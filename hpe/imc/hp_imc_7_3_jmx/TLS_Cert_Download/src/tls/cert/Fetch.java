package tls.cert;

import java.io.IOException;
import java.net.SocketException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


public class Fetch {
	private String ip;
	private int port;
	
	public Fetch(String ip, int port) {
		this.ip = ip;
		this.port = port;
	}
	
	public ArrayList<Certificate> getCerts() throws KeyManagementException {
		ArrayList<Certificate> certs = new ArrayList<Certificate>();
		
		try {
			
			URL url = new URL("https://" + ip + ":" + port);
			SSLContext ctx = SSLContext.getInstance("TLS");
			
			ctx.init(null, new TrustManager[]{ new X509TrustManager() {

			    private X509Certificate[] accepted;

			    @Override
			    public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			    }

			    @Override
			    public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			        accepted = xcs;
			    }

			    @Override
			    public X509Certificate[] getAcceptedIssuers() {
			        return accepted;
			    }
			}}, null);
			
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			
			connection.setHostnameVerifier(new HostnameVerifier() {
			    @Override
			    public boolean verify(String string, SSLSession ssls) {
			        return true;
			    }
			});
			
			connection.setSSLSocketFactory(ctx.getSocketFactory());
			
			// if this is the cert we want, it will result in an exception
			try {
				connection.getResponseCode();	// issue request
			} catch (SocketException e) {
				System.out.println("Found possible cert...");
			}

			// collect certificates
			
			try {
			    Certificate[] certificates = connection.getServerCertificates();
			    for (Certificate cert: certificates) {
			    	certs.add(cert);
			    }
			} catch (IllegalStateException e) {
				System.err.println("Could not establish connection to " + this.ip);
			} finally {
				connection.disconnect();
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return certs;
	}
	
}
