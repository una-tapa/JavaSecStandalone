
// S:\sf\TS008\221\TS008221226\2022-01-31\eappprd3_debug_logs.tgz_unpack\logs

public class createCitrixSFPath {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		//String caseNumber = args[0];
		//String caseNumber = "TS006659752";
		String caseNumber = args[0]; 
		String path1 = caseNumber.substring(0, 5);
		String path2 = caseNumber.substring(5, 8);
        System.out.println("part1=" + path1);
        System.out.println("path2=" + path2); 
		System.out.println("S:\\sf\\" + path1 + "\\" + path2 + "\\" + caseNumber);
	}

}
