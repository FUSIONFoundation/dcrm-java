package org.fsn_cfc.service;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.core.Transaction;
import org.ethereum.crypto.HashUtil;
import org.ethereum.util.ByteUtil;
import org.fsn_cfc.fusiondcrm.FusionDCRM;
import org.fsn_cfc.util.ECDSASignature;
import org.fsn_cfc.util.ETHECKeyUtil;
import org.fsn_cfc.util.User;

public class TxETHService {


	public static void run(String tokenType) {
		
		Scanner sc = new Scanner(System.in);
		
		//@INPUT@ Input the number of Supreme Nodes
		System.out.println("\n##########################################################################################################################\n");
	    System.out.println("Please input the number of Supreme Nodes to generate the FUSION DCRM private key: (For example: 4)"); 
		System.out.println("\n##########################################################################################################################\n");
	    int userCount = 4;
		String inputUserCount = sc.nextLine();
	    userCount = inputUserCount.equals("") ? userCount : Integer.parseInt(inputUserCount);
		

		//DCRM Key generate
	    List<User> userList = FusionDCRM.keyGenerate(userCount);
	    
	    //Encrypted Private Key
	    BigInteger encX = userList.get(0).getEncX();        
	    //Generate DCRM public key
		ECPoint pk = userList.get(0).getPk();
		
		//Generate DCRM Address
	    byte[] xyPkByte =  pk.getEncoded(false);
	    byte[] addressByte =  HashUtil.sha3omit12(Arrays.copyOfRange(xyPkByte, 1, xyPkByte.length));
	    String address = ByteUtil.bytesToBigInteger(addressByte).toString(16);
	        
	    
	    //@INPUT@ Transfer some Rinkeby Testnet ETH to DCRM address
	    String inputTransferOk = null;
	    do{
	    	System.out.println("\n##########################################################################################################################\n");
	        System.out.println("Please tranfer some Rinkeby Testnet ETH to the DCRM Address: " + address + ", (For example: transfer 0.1 Rinkeby Testnet ETH)"); 
	        System.out.println("Do you complete the procedure of Transferring Rinkeby Testnet ETH? Yes or No? (For example: No)"); 
	        System.out.println("\n##########################################################################################################################\n");
	        inputTransferOk = sc.nextLine();
	    }while(!inputTransferOk.equals("Yes"));
	    
	    
		//@INPUT@ Input the receive Rinkeby Testnet Address
		String inputToAddress = null;
	    do {
	    	System.out.println("\n##########################################################################################################################\n");
	        System.out.println("Please input Ethereum Rinkeby Testnet Address to receive ETH, not with the prefix '0x': (For example: 0520e8e5e08169c4dbc1580dc9bf56638532773a )"); 
	        System.out.println("\n##########################################################################################################################\n");
	        inputToAddress  = sc.nextLine();
			if(inputToAddress.length()!=40) {
				System.out.println("You have input the wrong Ethereum Rinkeby Testnet Address, and please try again.");
			}
	    }while(inputToAddress.length()!=40);
	    
		byte[] toAddress = Hex.decode(inputToAddress);
	    
	    //@INPUT@ Input the transfer value
	    System.out.println("\n##########################################################################################################################\n");
	    System.out.println("Please input transfer value(Wei), and confirm you have the enough Rinkeby Testnet ETH(Wei) to transfer: (For example: 10000)"); 
	    System.out.println("\n##########################################################################################################################\n");
	    String inputValue  = sc.nextLine();
	    
	    byte[] value;
	    if(!inputValue.equals("")) {
	    	value = ByteUtil.longToBytesNoLeadZeroes(Long.parseLong(inputValue));
	    }else {
	    	value = ByteUtil.longToBytesNoLeadZeroes(Long.parseLong("10000"));
	    }
	
		//New DCRM test transaction
		byte[] gasPrice = ByteUtil.longToBytesNoLeadZeroes(1_000_000_000_000L);
		byte[] gasLimit = ByteUtil.longToBytesNoLeadZeroes(21000);		
		Transaction tx = new Transaction(ByteUtil.longToBytesNoLeadZeroes(0L),
		        gasPrice,
		        gasLimit,
		        toAddress,
		        value,
		        null,
		        4);
		
		//Generate the TX Hash for sign function
		byte[] txRawHashByte = tx.getRawHash();
		String txRawHashHex = Hex.toHexString(txRawHashByte);
		String msgHash = txRawHashHex;
	  			
	    //Generate DCRM signature 
	    ECDSASignature signature = FusionDCRM.sign(userList, encX, msgHash, tokenType);
	    FusionDCRM.verify(signature, msgHash, pk);
	    
	    
	    //calculate the recId
	    int recId = -1;
	    for (int i = 0; i < 4; i++) {
	        byte[] k = ETHECKeyUtil.recoverPubBytesFromSignature(i, signature.getR(), signature.getS(), txRawHashByte);
	        if (k != null && Arrays.equals(k, xyPkByte)) {
	            recId = i;
	            break;
	        }
	    }
	    signature.setRecoveryParam(recId);
	    
	
	    //Generate the signed transaction		
		int v = recId + 27;
		tx = new Transaction(ByteUtil.longToBytesNoLeadZeroes(0L),
		        gasPrice,
		        gasLimit,
		        toAddress,
		        value,
		        null,
		        ByteUtil.bigIntegerToBytes(signature.getR()),
		        ByteUtil.bigIntegerToBytes(signature.getS()),
		        (byte)v,
		        4);
		
		byte[] txByteArray = tx.getEncoded();
		String txHex = Hex.toHexString(txByteArray);
		
		//Send the signed tranaction to ethereum Rinkeby testnet
		System.out.println("\n##########################################################################################################################\n");
	    System.out.println("Successfully generate the FUSION DCRM signed transaction: 0x"+ txHex);
	    System.out.println("\nPlease paste the FUSION DCRM signed transaction to the Step 3 (https://www.myetherwallet.com/#offline-transaction) and press the \"SEND TRANSACTION\" button.");
	    System.out.println("\n##########################################################################################################################\n");

	    
	}	
}
