package org.fsn_cfc.main;

import java.security.Security;
import java.util.Scanner;

import org.fsn_cfc.service.TxBTCService;
import org.fsn_cfc.service.TxETHService;
public class DCRMTest {


	public static void main(String[] args) {
		
		sysSet();

		Scanner sc = new Scanner(System.in); 
		//@INPUT@ Input the type of Token
		
		String tokenType = null;
		do {
			System.out.println("\n##########################################################################################################################\n");
	        System.out.println("Please input the type of Token which you would like to test DCRM, ETH or BTC ? (For example: ETH)"); 
			System.out.println("\n##########################################################################################################################\n");
			tokenType = "ETH";
			String inputTokenType = sc.nextLine();
			tokenType = inputTokenType.equals("") ? tokenType : inputTokenType;
			if(!(tokenType.equals("BTC")||tokenType.equals("ETH"))) {
				System.out.println("You have input the wrong type of Token, please try again."); 
				tokenType = "";
			}
		}while(!(tokenType.equals("BTC")||tokenType.equals("ETH")));
		
        if(tokenType.equals("ETH")) {
        	TxETHService.run(tokenType);
        }else if(tokenType.equals("BTC")) {
        	TxBTCService.run(tokenType);
        }
		
	}
	
	
	private static void sysSet() {

		String osName = System.getProperty("os.name");
		if(osName.contains("Windows")) {
			System.loadLibrary("gmp");
		}
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
	}
}
