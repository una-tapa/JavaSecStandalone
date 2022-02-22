import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.KeyManager;

public class OpenKeyStore {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("Hello"); 
		
		String platform = System.getProperty("os.name");
		String keystoreName = null; 
		
		platform = platform.toLowerCase(); 
		if (platform.contains("win")) {
			keystoreName = "c:\\tmp\\key.p12"; 
		}
		else {
			keystoreName = "/tmp/key.p12"; 
		}
		
		System.out.println("os.name is " + platform + "\nTrying to load keystore: " + keystoreName + " using Keystore.load()"); 

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keystoreName), "WebAS".toCharArray());

        } catch (Throwable e) {
            System.out.println("Failed to read testkeys file. " + e.toString() + " message:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
        System.out.println("Successfully loaded keystore on Windows"); 


	}

}
