
package org.fsn_cfc.paillierp;

import java.math.BigInteger;

import org.fsn_cfc.pakey.*;
import org.squareup.jnagmp.Gmp;

public abstract class AbstractPaillier {
	
	
	/** Public Key allowing encryption. */
	protected PaPublicKey publicKey = null;

	
	
	
	
	
	public PaPublicKey getPublicKey()
	{
		if (publicKey==null) {
			return null;
		}
		return publicKey.getPublicKey(); 
	}
	
	
	

	public BigInteger encrypt(BigInteger m, BigInteger r)
	{
		return encrypt(m, r, publicKey);
	}
	
	
	public static BigInteger encrypt(BigInteger m, BigInteger r, PaPublicKey key) {
		return encrypt(m, r, key.getN(), key.getNS(), key.getNSPlusOne());
	}
	
	public static BigInteger encrypt(BigInteger m, BigInteger r, BigInteger n, BigInteger ns, BigInteger nSPlusOne) {
		if(!(PaPublicKey.inModN(m,ns))) {
			throw new IllegalArgumentException("m must be less than n^s");
		}

		if(!(PaPublicKey.inModNStar(r,n))) {
			throw new IllegalArgumentException("r must be relatively prime to n and 0 <= r < n");
		}
		
		return (n.add(BigInteger.ONE).modPow(m, nSPlusOne).multiply(r.modPow(ns, nSPlusOne))).mod(nSPlusOne);
	}
	
	
	
	
	
	
	
	

	public BigInteger cipherAdd(BigInteger c1, BigInteger c2)
	{
		if(!(publicKey.inModNSPlusOne(c1))) throw new IllegalArgumentException("c1 must be less than n^(s+1)");
		if(!(publicKey.inModNSPlusOne(c2))) throw new IllegalArgumentException("c2 must be less than n^(s+1)");
		return (c1.multiply(c2)).mod(publicKey.getNSPlusOne());	
	}
	
	public BigInteger cipherMultiply(BigInteger c1, BigInteger cons)
	{	
		if(!(publicKey.inModNSPlusOne(c1))) throw new IllegalArgumentException("c1 must be less than n^2");
		return Gmp.modPowSecure(c1, cons, publicKey.getNSPlusOne());		
	}
}
