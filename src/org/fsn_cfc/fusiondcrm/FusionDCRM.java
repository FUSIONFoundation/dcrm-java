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

package org.fsn_cfc.fusiondcrm;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.ethereum.util.ByteUtil;
import org.fsn_cfc.cmt.Commitment;
import org.fsn_cfc.cmt.MTDCommitment;
import org.fsn_cfc.cmt.Open;
import org.fsn_cfc.util.BitcoinParams;
import org.fsn_cfc.util.ECDSASignature;
import org.fsn_cfc.util.OtherParams;
import org.fsn_cfc.util.RandomUtil;
import org.fsn_cfc.util.User;
import org.fsn_cfc.zkp.ZkpKG;
import org.fsn_cfc.zkp.ZkpSignOne;
import org.fsn_cfc.zkp.ZkpSignTwo;
import org.spongycastle.util.encoders.Hex;
import org.fsn_cfc.util.OtherUtil;

public class FusionDCRM {
	
	
	
	public static List<User> keyGenerate(int userCnt) {
		
		List<User> userList = new ArrayList<User>();
		
		kgRoundOne(userList,userCnt);
		kgRoundTwo(userList);
		kgRoundThree(userList);
			
		return userList;
	}
	
	
	public static void kgRoundOne(List<User> userList, int userCnt) {
		
		BigInteger xShare, xShareRnd, encXShare;
		ECPoint yShare;		
		User temUser;
		
		MTDCommitment mpkEncXiYi;
		Open<BigInteger> openEncXiYi;
		Commitment cmtEncXiYi;
		
		
		for(int i=0 ; i<userCnt ; i++) {
			temUser = new User();
			xShare = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			yShare = BitcoinParams.G.multiply(xShare);
			
			xShareRnd = RandomUtil.randomFromZnStar(OtherParams.PaillPubKey.getN(), OtherParams.SecureRnd);
			encXShare = OtherParams.PaillEnc.encrypt(xShare, xShareRnd);
			
			mpkEncXiYi = MTDCommitment.multiLinnearCommit(OtherParams.SecureRnd, OtherParams.MPK, encXShare, new BigInteger(yShare.getEncoded()));
			openEncXiYi = mpkEncXiYi.cmtOpen();
			cmtEncXiYi = mpkEncXiYi.cmtCommitment();
			System.out.println("\n--Info: User "+i+" calculate Commitment in KG round ONE");
			
			temUser.setxShare(xShare);
			temUser.setyShare(yShare);
			temUser.setxShareRnd(xShareRnd);
			temUser.setEncXShare(encXShare);
			
			temUser.setMpkEncXiYi(mpkEncXiYi);
			temUser.setOpenEncXiYi(openEncXiYi);
			
			temUser.setCmtEncXiYi(cmtEncXiYi);
			
			userList.add(temUser);
		}
	}
	
	
	public static void kgRoundTwo(List<User> userList) {
		
		ZkpKG zkpKG;
		
		for(int i = 0; i < userList.size() ; i ++) {
			zkpKG = new ZkpKG(OtherParams.ZKParams, userList.get(i).getxShare(), OtherParams.SecureRnd, BitcoinParams.G, 
					userList.get(i).getEncXShare(), userList.get(i).getxShareRnd());
			
			userList.get(i).setZkpKG(zkpKG);
			
			System.out.println("\n--Info: User "+i+" calculate Zero-Knowledge in KG round TWO");
			
		}
		
	}
	
	
	public static void kgRoundThree(List<User> userList) {

		Boolean aborted = false;
		
		for (int i = 0; i < userList.size(); i++) {
			if (!MTDCommitment.checkcommitment(userList.get(i).getCmtEncXiYi(), userList.get(i).getOpenEncXiYi(), OtherParams.MPK)) {
				aborted = true;
				System.out.println("\n##Error####################: "+
						"\n KG Round 3, User "+i+"does not pass checking Commitment!");
			}
		}
		
		for (int i = 0; i < userList.size(); i++) {
			if (!userList.get(i).getZkpKG().verify(OtherParams.ZKParams, BitcoinParams.CURVE, 
					BitcoinParams.CURVE.getCurve().decodePoint(userList.get(i).getOpenEncXiYi().getSecrets()[1].toByteArray()),
					userList.get(i).getOpenEncXiYi().getSecrets()[0])) {
				aborted = true;				
				System.out.println("\n##Error####################: "+
						"\n KG Round 3, User "+i+"does not pass verifying Zero-Knowledge!");
			}			
		}
		for (int i = 0; i < userList.size(); i++) {
			userList.get(i).setEncX(calculateEncPrivateKey(userList));
			userList.get(i).setPk(calculatePubKey(userList));
		}
	}
	
	
	
	
	public static ECPoint calculatePubKey(List<User> userList) {
		
		ECPoint pubKey = userList.get(0).getyShare();
		
		for(int i = 1; i < userList.size() ; i++) {
			pubKey = pubKey.add(userList.get(i).getyShare());
		}
		
		ECPoint pkTem = pubKey.normalize();
		String xPk_ = OtherUtil.convertBytesToHexString(pkTem.getX().toBigInteger().toByteArray());
		String yPk_ = OtherUtil.convertBytesToHexString(pkTem.getY().toBigInteger().toByteArray());
		String xPk = OtherUtil.subLast64(xPk_);
		String yPk = OtherUtil.subLast64(yPk_);
		
		System.out.println("\n--Info: Calculate the Public Key"+
				"\n PublicKey: "+"("+xPk+","+yPk+")");
		
		return pubKey;
	}
	
	
	
	
	public static BigInteger calculateEncPrivateKey(List<User> userList) {
		
		BigInteger encX = userList.get(0).getEncXShare();
		
		for(int i = 1; i < userList.size() ; i++) {
			encX = OtherParams.PaillEnc.cipherAdd(encX, userList.get(i).getEncXShare());
		}
		
		System.out.println("\n--Info: Calculate the Encrypted Private Key"+
				"\n EncPrivateKey: "+encX);

		
		BigInteger xTem = OtherParams.PaillDec.decrypt(encX).mod(BitcoinParams.q);
		String xTemHex = OtherUtil.subLast64(OtherUtil.convertBytesToHexString(xTem.toByteArray()));
		
		return encX;
	}
	
	
	
	
	
	public static void signRoudOne(List<User> userList, BigInteger encX) {
		
		BigInteger rhoI, rhoIRnd, uI, vI;
		
		MTDCommitment mpkUiVi;
		Open<BigInteger> openUiVi;
		Commitment cmtUiVi;
		
		
		for(int i = 0; i < userList.size() ; i ++) {
			
			rhoI = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			rhoIRnd = RandomUtil.randomFromZnStar(OtherParams.PaillPubKey.getN(), OtherParams.SecureRnd);
			
			uI = OtherParams.PaillEnc.encrypt(rhoI, rhoIRnd);
			vI = OtherParams.PaillEnc.cipherMultiply(encX, rhoI);
			
			mpkUiVi = MTDCommitment.multiLinnearCommit(OtherParams.SecureRnd, OtherParams.MPK, uI, vI);
			openUiVi = mpkUiVi.cmtOpen();
			cmtUiVi = mpkUiVi.cmtCommitment();

			userList.get(i).setRhoI(rhoI);
			userList.get(i).setRhoIRnd(rhoIRnd);
			userList.get(i).setuI(uI);
			userList.get(i).setvI(vI);
			userList.get(i).setMpkUiVi(mpkUiVi);
			userList.get(i).setOpenUiVi(openUiVi);
			
			userList.get(i).setCmtUiVi(cmtUiVi);
			
			System.out.println("\n--Info: User "+i+" calculate Commitment in Signning round ONE");
			
		}
		
	}
	
	
	
	
	public static void signRoudTwo(List<User> userList, BigInteger encX) {
	
		ZkpSignOne zkp1;
		
		for(int i = 0; i < userList.size() ; i ++) {
			zkp1 = new ZkpSignOne(OtherParams.ZKParams, userList.get(i).getRhoI(), OtherParams.SecureRnd, userList.get(i).getRhoIRnd(), 
					userList.get(i).getvI(), encX, userList.get(i).getuI());
			
			userList.get(i).setZkp1(zkp1);
			
			System.out.println("\n--Info: User "+i+" calculate Zero-Knowledge in Signning round TWO");
			
		}
	}

	
	

	public static BigInteger calculateU(List<User> userList) {
		BigInteger u;
		
		u = userList.get(0).getOpenUiVi().getSecrets()[0];
		for (int i = 1; i < userList.size(); i++) {
			u = OtherParams.PaillEnc.cipherAdd(u, userList.get(i).getOpenUiVi().getSecrets()[0]);
		}

		System.out.println("\n--Info: Calculate the Encrypted Inner-Data u"+
				"\n u: "+u);
		
		return u;
	}
	
	
	
	public static BigInteger calculateV(List<User> userList) {
		BigInteger v;
		
		v = userList.get(0).getOpenUiVi().getSecrets()[1];
		for (int i = 1; i < userList.size(); i++) {
			v = OtherParams.PaillEnc.cipherAdd(v, userList.get(i).getOpenUiVi().getSecrets()[1]);
		}

		System.out.println("\n--Info: Calculate the Encrypted Inner-Data v"+
				"\n v: "+v);
		
		return v;
	}

	
	
	
	public static Boolean signRoundThree(List<User> userList, BigInteger encX) {
		
		Boolean aborted = false;
				
		for (int i = 0; i < userList.size(); i++) {
			if (!MTDCommitment.checkcommitment(userList.get(i).getCmtUiVi(), userList.get(i).getOpenUiVi(), OtherParams.MPK)) {
				aborted = true;
				System.out.println("\n##Error####################: "+
						"\n SignRound 3, User "+i+"does not pass checking Commitment!");
				return aborted;
			}
		}
		
		for (int i = 0; i < userList.size(); i++) {
			if (!userList.get(i).getZkp1().verify(OtherParams.ZKParams, BitcoinParams.CURVE, userList.get(i).getOpenUiVi().getSecrets()[1], 
					encX, userList.get(i).getOpenUiVi().getSecrets()[0])) {

				aborted = true;				
				System.out.println("\n##Error####################: "+
						"\n SignRound 3, User "+i+"does not pass verifying Zero-Knowledge!");
				return aborted;
			}			
		}
		
		
		BigInteger u = calculateU(userList);
		BigInteger v = calculateV(userList);
		
		
		BigInteger kI, cI, cIRnd;
		ECPoint rI;

		BigInteger mask, wI;
		
		MTDCommitment mpkRiWi;
		Open<BigInteger> openRiWi;
		Commitment cmtRiWi;
		

		for (int i = 0; i < userList.size(); i++) {
			kI = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			rI = BitcoinParams.G.multiply(kI);
			
			cI = RandomUtil.randomFromZn(BitcoinParams.q, OtherParams.SecureRnd);
			cIRnd = RandomUtil.randomFromZnStar(OtherParams.PaillPubKey.getN(),OtherParams.SecureRnd);
			
			mask = OtherParams.PaillEnc.encrypt(BitcoinParams.q.multiply(cI), cIRnd);
			wI = OtherParams.PaillEnc.cipherAdd(OtherParams.PaillEnc.cipherMultiply(u, kI), mask);
			
			mpkRiWi = MTDCommitment.multiLinnearCommit(OtherParams.SecureRnd, OtherParams.MPK, new BigInteger(rI.getEncoded()), wI);
			openRiWi = mpkRiWi.cmtOpen();
			cmtRiWi = mpkRiWi.cmtCommitment();
			
			userList.get(i).setkI(kI);
			userList.get(i).setcI(cI);
			userList.get(i).setcIRnd(cIRnd);
			userList.get(i).setrI(rI);
			
			userList.get(i).setMask(mask);
			userList.get(i).setwI(wI);
			
			userList.get(i).setMpkRiWi(mpkRiWi);
			userList.get(i).setOpenRiWi(openRiWi);
			userList.get(i).setCmtRiWi(cmtRiWi);
			
			System.out.println("\n--Info: User "+i+" calculate Commitment in Signning round THREE");
			
		}
		
		return aborted;
	}
	
	
	
	
	
	
	public static void signRoundFour(List<User> userList, BigInteger u) {

		ZkpSignTwo zkp2;
		
		for (int i = 0; i < userList.size(); i++) {	
			zkp2 = new ZkpSignTwo(OtherParams.ZKParams, userList.get(i).getkI(), userList.get(i).getcI(), OtherParams.SecureRnd, BitcoinParams.G, 
					userList.get(i).getwI(), u, userList.get(i).getcIRnd());
			
			userList.get(i).setZkp_i2(zkp2);
			
			System.out.println("\n--Info: User "+i+" calculate Zero-Knowledge in Signning round FOUR");
			
		}
		
	}
	
	
	
	
	
	
	
	public static BigInteger calculateW(List<User> userList) {
		BigInteger w;
		
		w = userList.get(0).getOpenRiWi().getSecrets()[1];
		for (int i = 1; i < userList.size(); i++) {
			w = OtherParams.PaillEnc.cipherAdd(w, userList.get(i).getOpenRiWi().getSecrets()[1]);
		}
		
		System.out.println("\n--Info: Calculate the Encrypted Inner-Data w"+
				"\n w: "+w);
		
		return w;
	}
	
	
	
	
	
	
	public static ECPoint calculateR(List<User> userList) {
		ECPoint R;
		
		R= BitcoinParams.CURVE.getCurve().decodePoint(userList.get(0).getOpenRiWi().getSecrets()[0].toByteArray());
		for (int i = 1; i < userList.size(); i++) {
			R = R.add(BitcoinParams.CURVE.getCurve().decodePoint(userList.get(i).getOpenRiWi().getSecrets()[0].toByteArray()));
		}
		
		System.out.println("\n--Info: Calculate the Encrypted Inner-Data R"+
				"\n R: "+R.normalize().toString());
		
		return R;
	}
	
	
	
	public static ECDSASignature signRoundFive(List<User> userList, BigInteger u, BigInteger v, String message) {
		
		ECDSASignature signature = new ECDSASignature();		
		Boolean aborted = false;		
		
		for (int i = 0; i < userList.size(); i++) {
			if (!MTDCommitment.checkcommitment(userList.get(i).getCmtRiWi(), userList.get(i).getOpenRiWi(), OtherParams.MPK)) {
				aborted = true; 
				System.out.println("\n##Error####################: "+
						"\n SignRound 5, User "+i+"does not pass checking Commitment!");
				signature.setRoudFiveAborted(aborted);
			}
		}
		
		for (int i = 0; i < userList.size(); i++) {
			if (!userList.get(i).getZkp_i2().verify(OtherParams.ZKParams, BitcoinParams.CURVE, 
					BitcoinParams.CURVE.getCurve().decodePoint(userList.get(i).getOpenRiWi().getSecrets()[0].toByteArray()), 
					u, userList.get(i).getOpenRiWi().getSecrets()[1])){
				aborted = true;
				System.out.println("\n##Error####################: "+
						"\n SignRound 5, User "+i+"does not pass verifying Zero-Knowledge!");
				signature.setRoudFiveAborted(aborted);
			}
		}
		


		BigInteger w = calculateW(userList);
		ECPoint R = calculateR(userList);
				
		BigInteger r, mu;
		
		r = R.normalize().getX().toBigInteger().mod(BitcoinParams.q);
		
		mu = OtherParams.PaillDec.decrypt(w).mod(BitcoinParams.q);
		
		BigInteger muInverse, mMultiU, rMultiV, sEnc, s;
		
		muInverse = mu.modInverse(BitcoinParams.q);
		
		BigInteger msgDigest = new BigInteger(message, 16);
		
		mMultiU = OtherParams.PaillEnc.cipherMultiply(u, msgDigest);
		
		rMultiV = OtherParams.PaillEnc.cipherMultiply(v, r);
		
		sEnc = OtherParams.PaillEnc.cipherMultiply(OtherParams.PaillEnc.cipherAdd(mMultiU, rMultiV), muInverse);
		
		s = OtherParams.PaillDec.decrypt(sEnc).mod(BitcoinParams.q);

		signature.setRoudFiveAborted(aborted);
		signature.setR(r);
		signature.setS(s);
		
		
        if(s.compareTo(BitcoinParams.q.shiftRight(1))>0) {
        	s = BitcoinParams.q.subtract(s);
        	signature.setS(s);
        }
        
		return signature;
	}
	
	
	
	
	public static ECDSASignature sign(List<User> userList, BigInteger encX, String message) {
		
		signRoudOne(userList, encX);
		signRoudTwo(userList, encX);
		
		Boolean roudThreeAborted = signRoundThree(userList, encX);
		if(roudThreeAborted) {
			return null;
		}
		

		BigInteger u = calculateU(userList);
		BigInteger v = calculateV(userList);
		
		
		signRoundFour(userList, u);
		
		
		ECDSASignature signature = signRoundFive(userList, u, v, message);
		if(signature.getRoudFiveAborted()) {
			return null;
		}
        
		
		return signature;
	}
	
	
	public static Boolean verify(ECDSASignature signature, String message, ECPoint pk) {
		
		return signature.verify(message, pk);
	}

	
}
