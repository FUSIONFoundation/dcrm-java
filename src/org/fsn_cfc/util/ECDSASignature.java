package org.fsn_cfc.util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.util.ByteUtil;

public class ECDSASignature {
	
	private BigInteger r;
	
	private BigInteger s;
	
	private int recoveryParam;
	
	private Boolean roudFiveAborted;

	
	public ECDSASignature() {}
	
	public ECDSASignature(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;		
	}
	
	public ECDSASignature(BigInteger r, BigInteger s, int recoveryParam) {
		this.r = r;
		this.s = s;
		this.recoveryParam = recoveryParam;
	}
	

	public Boolean verify(String message, ECPoint pk) {
		
		BigInteger z = ByteUtil.bytesToBigInteger(Hex.decode(message));
		
		BigInteger u1 = (z.multiply(s.modInverse(BitcoinParams.q))).mod(BitcoinParams.q);
		BigInteger u2 = (r.multiply(s.modInverse(BitcoinParams.q))).mod(BitcoinParams.q);
		
		BigInteger xR = (BitcoinParams.G.multiply(u1).add(pk.multiply(u2))).getX().toBigInteger().mod(BitcoinParams.q);

		
		if(xR.equals(r)) {
			System.out.println("\n\n--Info: ECDSA Signature Verify Passed!"+
					"\n (r,s,v)=("+ r.toString(16) +", "+ s.toString(16) +", "+recoveryParam+") is a Valid Siganture!\n\n");			
			return true;
		}else {
			System.out.println("\n\n@@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed!"+
					"\n (r,s)=("+ r.toString(16) +","+ s.toString(16) +") is a InValid Siganture!\n\n");
			return false;
		}
	}
	
	
	
	

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "(r,s,recoveryParams)=("+ r +","+ s + "," + recoveryParam +")";
	}
	
	
	

	public Boolean getRoudFiveAborted() {
		return roudFiveAborted;
	}

	
	public void setRoudFiveAborted(Boolean roudFiveAborted) {
		this.roudFiveAborted = roudFiveAborted;
	}
	

	public BigInteger getR() {
		return r;
	}


	public void setR(BigInteger r) {
		this.r = r;
	}


	public BigInteger getS() {
		return s;
	}


	public void setS(BigInteger s) {
		this.s = s;
	}

	public int getRecoveryParam() {
		return recoveryParam;
	}

	public void setRecoveryParam(int recoveryParam) {
		this.recoveryParam = recoveryParam;
	}
	
	
}
