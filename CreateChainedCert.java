import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import javax.security.cert.X509Certificate;

import com.ibm.security.certclient.base.PkRejectionException;
import com.ibm.security.certclient.util.PkNewCertFactory;
import com.ibm.security.certclient.util.PkNewCertificate;

/*
 *  This program takes path to a keystore as an input. 
 *  Using the certificate in the keystore as a root, creates a chained certificate.  
 *   
 */
public class CreateChainedCert {
	
	static final String ROOT = "test";
	static int KEY_SIZE = 2048;
	static String SUBJECT_DN = "CN=localhost,OU=root";
	static String SUBJECT_ALT_NAMES = "subjectAltNames";	
	static int VALID_DAYS = 365; 

	

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		System.out.println("****Input parameters ****"); 
		System.out.println("FileName:" + args[0]); 
		System.out.println("password:" + args[1]); 
		//System.out.println("length=" + args.length);
		System.out.println("\n"); 

		
		String fileName = args[0].trim();
		String password = args[1].trim();
		
		System.out.println("\n**** Java information****"); 
		System.out.println(System.getProperty("java.version")); 
		System.out.println(System.getProperty("java.vm.name")); 
		System.out.println(System.getProperty("java.runtime.version")); 
		System.out.println("\n"); 


		
		CreateChainedCert ccc = new CreateChainedCert();
		PkNewCertificate chainedCert = null;
		
		try {
			KeyStore ks = ccc.getKeyStore(fileName, password); 
			
            //ccc.printAliases(ks); 

			
			java.security.cert.X509Certificate[] signing_cert_chain= ccc.getSigningCertChain(ks);
			PrivateKey signing_cert_private_key = ccc.getSigningCertPrivateKey(ks, password); 
			java.security.KeyPair keyPair = null; 
			
			System.out.println("\nUsing the key as a root, creating a chained certificate"); 
			
			chainedCert =ccc.newChainedCert(
					KEY_SIZE, 
					SUBJECT_DN, 
					VALID_DAYS, 
					getDeltaDate(), 
					true,  
					buildList(SUBJECT_ALT_NAMES), 
					buildList(null),  //kUsage, 
					buildList(null),  //extKUsage, 
					"IBMJCE", //provider, 
					keyPair, //keypair,
					signing_cert_chain, 
					signing_cert_private_key, 
					true); //CA			
			
			writeChainedCertToFile(fileName, chainedCert); 
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		

        System.out.println("Done!!!\n"); 
	
	}
	
	public static void writeChainedCertToFile(String fileName, PkNewCertificate chainCert) throws Exception {
		
		java.security.cert.X509Certificate[] chainedCert = chainCert.getCertificateChain();

		System.out.println("\nWriting the chained certificate"); 
		for (int i=0; i< chainedCert.length; i++) {
			System.out.println("CERT chain number " + i + " is: ");
			System.out.println(chainedCert[i]);
		}
		
		System.out.println("fileName=" + fileName); 
		String[] parts = fileName.split(Pattern.quote("."));
		
		String outputfile = "outputfile.p12"; 
		if (parts.length == 2) {
			outputfile = parts[0] + "Output." + parts[1]; 
		} 
		System.out.println("Output file:" + outputfile);
	
		//Set the certificate to a PKCS12 keystore
		KeyStore ks = KeyStore.getInstance("PKCS12");
		File file = new File(outputfile);
		if (file.exists()){
			//ks.load(new FileInputStream(file), "123456".toCharArray());
			ks.load(new FileInputStream(file), null);
		} else {
			ks.load(null, null);
		}

		ks.setKeyEntry("test", chainCert.getKey(), 
				"123456".toCharArray(),
				chainedCert);

		ks.store(new FileOutputStream(file), "123456".toCharArray());

	}
	
	
	
	public static Date getDeltaDate() {
		Date deltaDate = new Date();
		deltaDate.setTime(deltaDate.getTime() - (1 * 24 * 60 * 60 * 1000L));
		return deltaDate;		
	}
	
	void printAliases(KeyStore ks) throws Exception  {
		System.out.println("Printing aliases in the KeyStore"); 
		Enumeration aliases = ks.aliases(); 
        while (aliases.hasMoreElements())
        {
            String alias = (String) aliases.nextElement();
            System.out.println("alias=" + alias); 
        }
        System.out.println("Alias printed"); 
	}
	
	
	public KeyStore getKeyStore(String fileName, String password) {
		
		KeyStore ks = null; 
		
		try {
			ks = getKeyStore(fileName, password, "PKCS12");
		} 
		catch (Exception e) {
			try {
				ks = getKeyStore(fileName, password, "JKS");				
			}
			catch (Exception ee) {
				ee.printStackTrace();
			}
		}
		return ks; 		
	}
	
	public KeyStore getKeyStore(String fileName, String password, String storeType) throws Exception {
		//Set the certificate to a PKCS12 keystore
		String alias = "root"; 

		KeyStore ks = KeyStore.getInstance(storeType);
		File file = new File(fileName);
		if (file.exists()){
			ks.load(new FileInputStream(file), password.toCharArray());
		} else {
			ks.load(null, null);
		}
		
		//System.out.println("Returning ks=" + ks);
		return ks;
	}
	
	public static List buildList (String stringVal) {

		List listVal = (List) new ArrayList();
		if (stringVal == null) {
			listVal = null; 
		}
		else {

			String[] values = stringVal.split(",");
			for (String val : values) {
				((ArrayList) listVal).add(val);
			}
		}
		return listVal;
	}
	
	public java.security.cert.X509Certificate[] getSigningCertChain(KeyStore ks) throws Exception {
		
		java.security.cert.X509Certificate[] rootCertChainX509 = null; 
		
		if (ks.containsAlias(ROOT)) {
			Certificate[] rootCertChain = (Certificate[]) ks.getCertificateChain(ROOT);
			Certificate cert  = ks.getCertificate(ROOT);
			

			if (rootCertChain != null)
			{
				// convert to an X509Certificate[]
				rootCertChainX509 = new java.security.cert.X509Certificate[rootCertChain.length];
				for (int i = 0; i < rootCertChain.length; i++)
				{
					rootCertChainX509[i] = (java.security.cert.X509Certificate) rootCertChain[i];
				}
			}			
		}
		else {
			System.out.println("Keystore does not contain the alias:" + ROOT); 
		}
		//System.out.println("Returning rootCertChainX509=" + rootCertChainX509 ); 
		return rootCertChainX509; 
		
	}
	
	public PrivateKey getSigningCertPrivateKey(KeyStore ks, String password) throws Exception { 
		PrivateKey rootPrivateKey = (java.security.PrivateKey) ks.getKey(ROOT, password.toCharArray()); 
		//System.out.println("Returning rootPrivateKey=" + rootPrivateKey ); 
        return rootPrivateKey; 
	}
	
	
	public PkNewCertificate newChainedCert(int keySize, java.lang.String subjectDN, int numValidDays, java.util.Date notBefore, boolean useShortSubjectKId, 
			java.util.List subjectAltNames, java.util.List kUsage, java.util.List extKUsage, java.lang.String provider, 
			java.security.KeyPair keyPair, java.security.cert.X509Certificate[] signing_cert_chain, java.security.PrivateKey signing_cert_private_key, boolean CA) 
	throws PkRejectionException
	{	

        System.out.println("newChainedCert Entry");
        
		traceNewCert(keySize, subjectDN, numValidDays, notBefore, useShortSubjectKId, subjectAltNames, 
				kUsage, extKUsage, provider, keyPair, signing_cert_chain, signing_cert_private_key, CA);
		
		PkNewCertificate newCert = null; 
		try {
			newCert = PkNewCertFactory.newCert(keySize, subjectDN, numValidDays, notBefore, useShortSubjectKId, subjectAltNames, 
					kUsage, extKUsage, provider, keyPair, signing_cert_chain, signing_cert_private_key, CA);
		} catch (PkRejectionException Pkre1) {
			try {
		        
		        	System.out.println("Tried useShortSubjectKId=" + useShortSubjectKId + " and received exception: " + Pkre1.toString() + " message=" + Pkre1.getMessage());  
		        	System.out.println("Retrying with useShortSubjectKId=" + !useShortSubjectKId);
				//Flip useShortSubjectKId trying to match SKI/AKI  
				newCert = PkNewCertFactory.newCert(keySize, subjectDN, numValidDays, notBefore, !useShortSubjectKId, subjectAltNames, 
						kUsage, extKUsage, provider, keyPair, signing_cert_chain, signing_cert_private_key, CA);
			} catch (PkRejectionException Pkre2) {
                  System.out.println("Tried short/long Subject KId. and received exception: " + Pkre2.toString() + " message=" + Pkre2.getMessage());  
                  throw Pkre2; 
			}
		} 
       System.out.println("newChainedCert Exit");
		return newCert; 
	}
	
	public static void traceNewCert(int keySize, java.lang.String subjectDN, int numValidDays, java.util.Date notBefore, boolean useShortSubjectKId, 
			java.util.List subjectAltNames, java.util.List kUsage, java.util.List extKUsage, java.lang.String provider, 
			java.security.KeyPair keyPair, java.security.cert.X509Certificate[] signing_cert_chain, java.security.PrivateKey signing_cert_private_key, boolean CA) {
		
		String msg = "Creating a new chained certificate:" + 
				" keySize=" + keySize +  
				" subjectDN=" + subjectDN + 
				" validDays=" + numValidDays + 
				" deltaDate=" + notBefore.toString() + 
				" useSubjectShortKId=" + useShortSubjectKId + 
				" subjectAltNames " + subjectAltNames + 
				" keyUsage=" + kUsage + 
				" ExtendedKeyUsage=" + extKUsage + 
				" provider=" + provider + 
				" keyPair=" + keyPair + 
				" signing_cert_chain=" + signing_cert_chain +
				" signing+cert_private_key=" + signing_cert_private_key +
				" isCA=" + CA;
		
        System.out.println(msg);
		//System.out.println("DEBUG: " + msg); 
		
	}

}
