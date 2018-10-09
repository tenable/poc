package tls.cert;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class CertManager {
	
	private KeyStore ks;
	private String password;
	private String keystoreFile;
	
	public CertManager(String password, String keystoreFile) {
		try {
			this.password = password;
			this.keystoreFile = keystoreFile;
			this.ks  = KeyStore.getInstance("JKS", "SUN");
			this.ks.load(new FileInputStream(keystoreFile), password.toCharArray());
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public boolean storeCert(String alias, Certificate cert) {
		boolean stored = false;
		try {
		FileOutputStream fos = new FileOutputStream(this.keystoreFile);
		this.ks.setCertificateEntry(alias, cert);
		this.ks.store(fos, this.password.toCharArray());
		stored = true;
		fos.close();
		} catch (FileNotFoundException e) {
			System.out.println("Error reading keystore file: \n" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return stored;
	}
	
	public boolean deleteCert(String alias) {
		boolean deleted = false;
		try {
			FileOutputStream fos = new FileOutputStream(this.keystoreFile);
			this.ks.deleteEntry(alias);
			this.ks.store(fos, this.password.toCharArray());
			deleted = true;
			fos.close();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			System.out.println("Error reading keystore file: \n" + e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return deleted;
	}
}
