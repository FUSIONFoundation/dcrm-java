/*
This software is a demonstration and verification of the FUSION’s distributed 
private key management technology and the core function of realizing cross-chain 
asset management.
Copyright（C） 2018  FUSION Foundation
This program is open source and is licensed by the FUSION Foundation, the copyright 
owner, to the FUSION Community for free use and download. Users can copy and 
disseminate the software, subject to the retention of this copyright notices. 
Users can modify the software, and the modification part can add author’s information 
and independent copyright notice, but the source code of the modified part must be 
fed back to FUSION community in an open source way, and be licensed to FUSION community 
and community members to use it freely. Users can use part or all of this software 
in their program, but at the same time, the part of the reference should be clearly 
marked with this copyright notice. Users are required to contact FUSION Foundation, 
the copyright owner, and obtain authorization when they want to use part or all of this 
software for commercial purposes.
The purpose of issuing this procedure is to make it useful, but without any warranty, 
and even without implied warranties for specific purposes.
FUSION foundation, as the copyright owner, reserves the right to claim the software 
copyright and the right to change the copyright notice, but all changes do not affect 
the license to the FUSION community.
The copyright notice is attached to the source code of this software. If necessary, 
you can also contact the FUSION Foundation (https://www.fusion.org/), and add 
information on how to keep in touch with you.
*/

package org.fsn_cfc.test;

import java.math.BigInteger;
import java.security.Security;
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
import org.fsn_cfc.util.ECKeyUtil;
import org.fsn_cfc.util.User;

public class DCRMSign {


	public static void main(String[] args) {
		
		
		String osName = System.getProperty("os.name");
		if(osName.contains("Windows")) {
			System.loadLibrary("gmp");
		}
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		
		//@INPUT@ Input the number of Supreme Nodes
		Scanner sc = new Scanner(System.in); 
		System.out.println("\n##########################################################################################################################\n");
        System.out.println("Please input the number of Supreme Nodes to generate the FUSION DCRM private key: (For example: 4)"); 
		System.out.println("\n##########################################################################################################################\n");
        String inputUserCount = sc.nextLine();
        int userCount = 4;
		if(!inputUserCount.equals(""))
			userCount = Integer.parseInt(inputUserCount);
		
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
        String inputTransferOk = "";
        do{
        	System.out.println("\n##########################################################################################################################\n");
            System.out.println("Please tranfer some Rinkeby Testnet ETH to the DCRM Address: 0x" + address + ", (For example: transfer 0.1 Rinkeby Testnet ETH)"); 
	        System.out.println("Do you complete the procedure of Transferring Rinkeby Testnet ETH? Yes or No? (For example: No)"); 
	        System.out.println("\n##########################################################################################################################\n");
	        inputTransferOk = sc.nextLine();
        }while(!inputTransferOk.equals("Yes"));
        		
		//@INPUT@ Input the receive Rinkeby Testnet Address
		String inputToAddress = "0520e8e5e08169c4dbc1580dc9bf56638532773a";
        do {
        	System.out.println("\n##########################################################################################################################\n");
            System.out.println("Please input Ethereum Rinkeby Testnet Address to receive ETH, not with the prefix '0x': (For example: 0520e8e5e08169c4dbc1580dc9bf56638532773a)"); 
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
        ECDSASignature signature = FusionDCRM.sign(userList, encX, msgHash);
        FusionDCRM.verify(signature, msgHash, pk);
        
        
        //calculate the recId
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            byte[] k = ECKeyUtil.recoverPubBytesFromSignature(i, signature.getR(), signature.getS(), txRawHashByte);
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
