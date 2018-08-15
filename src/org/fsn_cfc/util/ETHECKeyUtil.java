package org.fsn_cfc.util;

import java.math.BigInteger;

import org.ethereum.crypto.ECKey;


public class ETHECKeyUtil {

	public static byte[] recoverPubBytesFromSignature(int recId, BigInteger r, BigInteger s, byte[] messageHash) {
		
		ECKey.ECDSASignature sig = new ECKey.ECDSASignature(r, s).toCanonicalised();
		
		return ECKey.recoverPubBytesFromSignature(recId, sig, messageHash);
	}

}
