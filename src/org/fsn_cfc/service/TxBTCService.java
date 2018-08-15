package org.fsn_cfc.service;

import java.math.BigInteger;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.math.ec.ECPoint;
import org.fsn_cfc.fusiondcrm.FusionDCRM;
import org.fsn_cfc.util.BTCAPIUtil;
import org.fsn_cfc.util.BTCUtil;
import org.fsn_cfc.util.Base58Util;
import org.fsn_cfc.util.ECDSASignature;
import org.fsn_cfc.util.OtherUtil;
import org.fsn_cfc.util.User;

public class TxBTCService {

	public static void run(String tokenType) {

		Scanner sc = new Scanner(System.in); 
		
		//@INPUT@ Input the number of Supreme Nodes
		System.out.println("\n##########################################################################################################################\n");
        System.out.println("Please input the number of Supreme Nodes to generate the FUSION DCRM private key: (For example: 4)"); 
		System.out.println("\n##########################################################################################################################\n");
	    int userCount = 4;
		String inputUserCount = sc.nextLine();
	    userCount = inputUserCount.equals("") ? userCount : Integer.parseInt(inputUserCount);

		//key generate
        List<User> userList = FusionDCRM.keyGenerate(userCount);
        
        //Encrypted Private Key
        BigInteger encX = userList.get(0).getEncX();
        
        //public key
        ECPoint pk = userList.get(0).getPk();
        String pkStr = userList.get(0).getPkStr();
        
        //calculate address
        String pkHex = "04"+ pkStr;
		String address = BTCUtil.ConvertPublicKeyToBitcoinAdress(pkHex);

		
		//@INPUT@ Transfer some Testnet BTC to DCRM address
        String inputTransferOk = null;
        
		String[] utxoV = null;
        do{
        	System.out.println("\n##########################################################################################################################\n");
            System.out.println("Please tranfer some Testnet BTC to the DCRM Address: " + address + ", (For example: transfer 0.1 Testnet BTC)"); 
	        System.out.println("Do you complete the procedure of Transferring Testnet BTC? Yes or No? (For example: No)"); 
	        System.out.println("\n##########################################################################################################################\n");
	        inputTransferOk = sc.nextLine();
	        
	        if(inputTransferOk.equals("Yes")) {
	    		utxoV = BTCAPIUtil.getUtxoByAddress(address);
	    		
	    		if(utxoV[0]=="address_error") {
	    			System.out.println("address_error!!");
	    			inputTransferOk = "No";
	    		}else if(utxoV[0]=="no_money"){
					System.out.println("You do not complete the procedure of Transferring Testnet BTC, and please try again.");
	    			inputTransferOk = "No";
	    		}else if(utxoV[0]=="wait_confirm") {
					System.out.println("The transfer transaction is waitting for confirmation, and please try again.");
	    			inputTransferOk = "No";
	    		}
	        }
        }while(!inputTransferOk.equals("Yes"));

        
		//@INPUT@ Input the receive Testnet Address
		String inputToAddress = null;
        do {
        	System.out.println("\n##########################################################################################################################\n");
            System.out.println("Please input Bitcoin Testnet Address (P2PKH, with the leading symbol m or n) to receive BTC, not with the prefix '0x': (For example: mwv8hYDLHaoA4DXMFNjBTX5VFosMbRVVvS )"); 
            System.out.println("\n##########################################################################################################################\n");
            inputToAddress  = sc.nextLine();
			if(inputToAddress.length()!=34) {
				System.out.println("You have input the wrong Bitcoin Testnet Address, and please try again.");
			}else if(!(inputToAddress.charAt(0)=='m' || inputToAddress.charAt(0)=='n')){
				System.out.println("The Bitcoin Testnet Address you have input is not the P2PKH Address which with the leading symbol m or n, and please try again.");
				inputToAddress = "";
			}
        }while(inputToAddress.length()!=34);
        	
		String fromAddress = address;
		String toAddress = inputToAddress;

		        		
		StringBuffer inBf = new StringBuffer();
		inBf.append("76");
		inBf.append("a9");
		inBf.append("14");
		inBf.append(Base58Util.Base58ToHexString(fromAddress, 50).substring(2, 42));
		inBf.append("88");
		inBf.append("ac");
		String inScript = inBf.toString();
		
		
		StringBuffer toBf = new StringBuffer();
		toBf.append("76");
		toBf.append("a9");
		toBf.append("14");
		toBf.append(Base58Util.Base58ToHexString(toAddress, 50).substring(2, 42));
		toBf.append("88");
		toBf.append("ac");
		String outScript = toBf.toString();

		
		String utxo =  utxoV[0];
		int utxoIndex = Integer.parseInt(utxoV[1]);
		int txValue =  Integer.parseInt(utxoV[2]);
		
		
		StringBuffer input = new StringBuffer();
		input.append(strBn2Ln(utxo));
		input.append(int2LnStr(utxoIndex, 8));
		input.append(Integer.toHexString(inScript.length()/2));
		input.append(inScript);
		input.append("ffffffff");
		String tx_input = input.toString();
		
		
		// miner fee is 10000 satoshi, 1 BTC = 10^8 satoshi
		int value = txValue - 10000;
		StringBuffer output = new StringBuffer();
		output.append(int2LnStr(value, 16));
		output.append(Integer.toHexString(outScript.length()/2));
		output.append(outScript);
		String tx_output = output.toString();
		

		int inCnt = 1;
		int outCnt = 1; 
		int version = 1;
		int lockTime = 0;
		StringBuffer txBf = new StringBuffer();
		txBf.append(int2LnStr(version, 8));
		txBf.append(strBn2Ln(int2LnStr(inCnt, 2)));
		txBf.append(tx_input);
		txBf.append(strBn2Ln(int2LnStr(outCnt, 2)));
		txBf.append(tx_output);
		txBf.append(int2LnStr(lockTime, 8));
		String tx = txBf.toString();
		
		
		StringBuffer rawTxBf = new StringBuffer(tx);
		//hashtype
		int hashType = 1;
		rawTxBf.append(int2LnStr(hashType, 8));
		String rawTx = rawTxBf.toString();
		
		
        //#################################################  generate raw_tx_hash  ###############################################
		String raw_tx_hash = BTCUtil.getHashSHA256_from_HexString(rawTx);
		raw_tx_hash = BTCUtil.getHashSHA256_from_HexString(raw_tx_hash);
		
		String msgHash = raw_tx_hash;
        ECDSASignature signature = FusionDCRM.sign(userList, encX, msgHash, tokenType);
        FusionDCRM.verify(signature, msgHash, pk);   
		

		
		StringBuffer DERSigBuf = new StringBuffer();
		String rHex = OtherUtil.convertBytesToHexString(signature.getR().toByteArray());
		String sHex = OtherUtil.convertBytesToHexString(signature.getS().toByteArray());
		int rLen = rHex.length()/2;
		int sLen = sHex.length()/2;
		int sigLen = rLen + sLen + 4;
		
		String rLenHex = int2LnStr(rLen,2);
		String sLenHex = int2LnStr(sLen,2);
		String sigLenHex = int2LnStr(sigLen,2);
		
		DERSigBuf.append("30");
		DERSigBuf.append(sigLenHex);
		DERSigBuf.append("02");
		DERSigBuf.append(rLenHex);
		DERSigBuf.append(rHex);
		DERSigBuf.append("02");
		DERSigBuf.append(sLenHex);
		DERSigBuf.append(sHex);
        
		String DERSig = DERSigBuf.toString() + int2LnStr(hashType, 2);
        
        
        
        //#################################################  generate signedScriptSig  ###############################################
		StringBuffer signedScriptSigBuffer = new StringBuffer(int2LnStr(DERSig.length()/2, 2));
		signedScriptSigBuffer.append(DERSig);
		signedScriptSigBuffer.append(int2LnStr(pkHex.length()/2, 2));
		signedScriptSigBuffer.append(pkHex);
		
		String signedScriptSig = signedScriptSigBuffer.toString();
		
        //#################################################  generate tx  ###############################################
		input = new StringBuffer();
		input.append(strBn2Ln(utxo));
		input.append(int2LnStr(utxoIndex, 8));
		input.append(Integer.toHexString(signedScriptSig.length()/2));
		input.append(signedScriptSig);
		input.append("ffffffff");
		tx_input = input.toString();
		
		
		
		txBf = new StringBuffer();
		txBf.append(int2LnStr(version, 8));
		txBf.append(strBn2Ln(int2LnStr(inCnt, 2)));
		txBf.append(tx_input);
		txBf.append(strBn2Ln(int2LnStr(inCnt, 2)));
		txBf.append(tx_output);
		txBf.append(int2LnStr(lockTime, 8));
		
		tx = txBf.toString();
		
		//Send the signed tranaction to ethereum Rinkeby testnet
		System.out.println("\n##########################################################################################################################\n");
	    System.out.println("Successfully generate the FUSION DCRM signed transaction: "+ tx);
	    System.out.println("\nPlease paste the FUSION DCRM signed transaction to the website (https://live.blockcypher.com/btc/pushtx/#) with the Network selection of \"Bitcoin Testnet\" and press the \"BROADCAST TRANSACTION\" button.");
	    System.out.println("\n##########################################################################################################################\n");

		
	}
	
	
			
	 private static String int2LnStr(int var0, int length) {
	        int var1 = 1;
	        int var2 = var0 >> 8;
	        int var3 = var0 & 255;
	        String var4 = Integer.toHexString(var2);
	        String var5 = Integer.toHexString(var3);
	        if(var4.length() > 2) {
	            do {
	                if(var1 > 1) {
	                    var2 >>= 8;
	                }
	                var4 = Integer.toHexString(var2 >> 8);
	                var5 = var5 + Integer.toHexString(var2 & 255);
	                ++var1;
	            } while(var4.length() > 2);
	        }
	        if(var4.length() < 2) {
	            var4 = "0" + var4;
	        }
	        if(var5.length() < 2) {
	            var5 = "0" + var5;
	        }
	        
	        String tem = var5 + var4;
	        StringBuffer result = new StringBuffer(tem);
	        
	        if(tem.length() < length) {
	        	for(int i = 0 ; i < length-tem.length() ; i++) {
	        		result.append(0);
	        	}
	        }
	        
	        if(tem.length() > length) {	        	
	        	for(int i = 0 ; i < tem.length() - length ; i++) {
	        		result.deleteCharAt(result.length()-1);
	        	}
	        }
	        
	        return result.toString();
	    }
	 
	 
	 
	 private static String strBn2Ln(String bn) {
		 char[] bnArray = bn.toCharArray();
		 
		 StringBuffer rlt = new StringBuffer();
		 
		 for(int i=bn.length()/2; i>0; i--) {
			 rlt.append(bnArray[i*2-2]);
			 rlt.append(bnArray[i*2-1]);
		 }
		 
		 return rlt.toString();
	 }
			
			
			
}
