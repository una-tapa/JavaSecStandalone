
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.*;
import javax.net.ssl.SSLSocketFactory;
import javax.net.SocketFactory;
import java.security.cert.Certificate;
import com.ibm.security.certclient.util.PkSsCertFactory;
import com.ibm.security.certclient.util.PkSsCertificate;
import com.ibm.security.certclient.util.PkNewCertificate;
import com.ibm.security.certclient.util.PkNewCertFactory;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.text.DateFormat;

public class selfSigned
{

	static int keySize = 2048;
	static String keyType = "RSA";
	static String sigAlg = "SHA256withRSA"; 
	static String subjectDN = "CN=localhost,OU=root"; 
	static int validDays = 365;
	static boolean useShortSubjectKId = true; 
	static List<String> subjectAltNames = new java.util.ArrayList<String>(); 
	static List<String> keyUsage = new java.util.ArrayList<String>(); 
	static List<String> extKeyUsage = new java.util.ArrayList<String>(); 
	static boolean isCA = false; 
	String provier = "IBMJCE"; 
	String keyStoreFileName = "testRootKey.p12"; 
	String keyStoreType = "PKCS12"; 
	String keyStorePassword ="123456"; 
	
	
	static void processInput(String[] args) {

		if (args.length == 0) {
			System.out.println("Please provide input parameters.");
			System.out.println("Example"); 
		}
		
		for(int i=0;i<args.length;i++)  {
			System.out.println("Processing input[" + i + "]:" + args[i]);  
			System.out.println("option=" +getOption(args[i]));
			String option = getOption(args[i]); 
			if (option != null) {
				System.out.println("value=" + args[i+1]); 
				processOptions(option, args[i+1]);
				i++; 
			}
			else {
				System.out.println("A value [" + args[i] + "] was found without option"); 
				System.exit(1);
			}
		} 	
	}
	
	static void processOptions(String option, String value) {
		if (option.equalsIgnoreCase(KEY_SIZE)) {
			processKeySize(value); 
		} 
		else if  (option.equalsIgnoreCase(KEY_TYPE)) {
			processKeyType(value); 
		} 
		else if (option.equalsIgnoreCase(SIG_ALG)) {
			processSigAlg(value); 
		}
		else if (option.equalsIgnoreCase(SUBJECT_DN)) {
			processSubjectDN(value); 
		}
		else if (option.equalsIgnoreCase(VALID_DAYS)) {
			processValidDays(value); 
		}
		else if (option.equalsIgnoreCase(USE_SHORT_SUBJECTKID)) {
			processShortSubjectKId(value); 
		}
		else if (option.equalsIgnoreCase(SUBJECT_ALT_NAMES)) {
			processSubjectAltNames(value); 
		}
		else if (option.equalsIgnoreCase(KEY_USAGE)) {
			processKeyUsage(value);
		}
		else if (option.equalsIgnoreCase(EXT_KEY_USAGE)) {
			processExtKeyUsage(value); 
		}
		else if (option.equalsIgnoreCase(IS_CA)) {
			processIsCA(value); 
		}
	}
	
	static void processKeySize(String value) {
		keySize = Integer.valueOf(value).intValue(); 
	}
	static void processKeyType(String value) {
		keyType = value; 
	}
	
	static void processSigAlg(String value) {
		sigAlg = value; 
	}

	static void processSubjectDN(String value) {
		subjectDN = value; 
	}
	
	static void processValidDays(String value) {
		validDays = Integer.valueOf(value).intValue(); 
	}
	
	static void processExtKeyUsage(String value) {
	}

	static void processShortSubjectKId(String value) {
		if (value !=null && value.equalsIgnoreCase("true")) {
			useShortSubjectKId = true;
		}
		else if (value !=null && value.equalsIgnoreCase("false")) {
			useShortSubjectKId = false; 
		}
	}
	
	static void processSubjectAltNames(String value) {
		String[] arrayOfSan= null;

		if (value!=null && value.length() !=0) {
			arrayOfSan = value.split(",");
		}

		for (int i=0; i < arrayOfSan.length; i++) {
			subjectAltNames.add(arrayOfSan[i]);
		}
	}

	static void processKeyUsage(String value) {
		
	}
	
	static void processIsCA(String value) {
		if (value !=null && value.equalsIgnoreCase("true")) {
			isCA = true;
		}
		else if (value !=null && value.equalsIgnoreCase("false")) {
			isCA = false; 
		}
	}
	
	static String getOption(String param) {
		
		String[] arrOfStr= null;
		String option = null; 
		
		if (param.startsWith("-")) {
			arrOfStr = param.split("-"); 
			option = arrOfStr[1]; 
		}
		return option; 
	}
	
	
	
	
	public static void main(String[] args)
	{
		processInput(args); 

		
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
		
		try {
			Date deltaDate = new Date();
			deltaDate.setTime(deltaDate.getTime() - (1 * 24 * 60 * 60 * 1000L));
			
			
			
			PkSsCertificate SsCert = PkSsCertFactory.newSsCert(
					2048,                                  //int keysize
					"RSA",                                 //String keytype
					"SHA256withRSA",                       //String signatureAlgorithm
					"CN=localhost,OU=root",                //String subjectDN
					365,                                   //number of Valid days
					deltaDate,                             //Date - not before 
					false,                                 //boolean useShortSubjectKId
					null,                                  //List subectAltNames
					null,                                  //List kUsage
					null,                                  //List extKUsage
					"IBMJCE",                              //String provider 
					null,                                  //KeyPair keyPair
					true);                                 //boolean isCA 

			X509Certificate rootCert = SsCert.getCertificate();
                        X509Certificate[] rootChain = new X509Certificate[1];
                        rootChain[0] = rootCert;
			PrivateKey rootPrivateKey = SsCert.getKey();
			System.out.println("root cert is " + rootCert);


			//Set the certificate to a PKCS12 keystore
			KeyStore ks = KeyStore.getInstance("PKCS12");
			File file = new File("testKey.p12");
			if (file.exists()){
				ks.load(new FileInputStream(file), "123456".toCharArray());
			} else {
				ks.load(null, null);
			}

			ks.setKeyEntry("test", rootPrivateKey, 
					"123456".toCharArray(),
					rootChain);

			ks.store(new FileOutputStream(file), "123456".toCharArray());


		} catch (Exception e ) {
			System.out.println("exception " + e.getMessage());
		}

	}
	
	
	static final String KEY_SIZE = "keySize"; 
	static final String KEY_TYPE = "keyType";
	static final String SIG_ALG  = "signatureAlgorithm"; 
	static final String SUBJECT_DN = "subjectDN"; 
	static final String VALID_DAYS = "validDays"; 
	static final String USE_SHORT_SUBJECTKID = "shortSubjectKeyId"; 
	static final String SUBJECT_ALT_NAMES = "subjectAltNames"; 
	static final String KEY_USAGE = "keyUsage"; 
	static final String EXT_KEY_USAGE = "extendedKeyUsage"; 
	static final String IS_CA = "isCA";
	
	//Key usages
	public static final String DIGITAL_SIGNATURE = "digital_signature";
	public static final String NON_REPUDIATION = "non_repudiation";
	public static final String KEY_ENCIPHERMENT = "key_encipherment";
	public static final String DATA_ENCIPHERMENT = "data_encipherment";
	public static final String CIPHER_ONLY = "encipher_only";
	public static final String DECIPHER_ONLY = "decipher_only";
	public static final String KEY_AGREEMENT = "key_agreement";
	public static final String KEY_CERT_SIGN = "keyCertSign";
	public static final String CRL_SIGN = "cRLSign";
	
	public static final List<String> KEY_USAGES = Arrays.asList(new String[]{
            DIGITAL_SIGNATURE,
			NON_REPUDIATION,
			KEY_ENCIPHERMENT,
			DATA_ENCIPHERMENT,
			KEY_AGREEMENT,
			KEY_CERT_SIGN,
			CRL_SIGN,
			CIPHER_ONLY,
			DECIPHER_ONLY,
	});
	
	//Key usage list
	public static final List<String> KEY_USAGES_ALLOWED = Arrays.asList(new String[]{
            DIGITAL_SIGNATURE,
			NON_REPUDIATION,
			KEY_ENCIPHERMENT,
			DATA_ENCIPHERMENT,
			CIPHER_ONLY,
			DECIPHER_ONLY,
	});
	
	//Extended key usages
	public static final String SERVER_AUTH = "ServerAuth_Id";
	public static final String CLIENT_AUTH = "ClientAuth_Id";
	public static final String CODE_SIGNING = "CodeSigning_Id";
	public static final String EMAIL_PROTECTION = "EmailProtection_Id";
	public static final String IPSEC_END = "IPSecEndSystem_Id";
	public static final String IPSEC_TUNNEL = "IPSecTunnel_Id";
	public static final String IPSEC_USER = "IPSecUser_Id";
	public static final String TIMESTAMPING = "TimeStamping_Id";
	
	//Extended key usage list
	public static final List<String> EXTENDED_KEY_USAGES = Arrays.asList(new String[]{
            SERVER_AUTH,
			CLIENT_AUTH,
			CODE_SIGNING,
			EMAIL_PROTECTION,
			IPSEC_END,
			IPSEC_TUNNEL,
			IPSEC_USER,
			TIMESTAMPING
	});
	
	
	

}


