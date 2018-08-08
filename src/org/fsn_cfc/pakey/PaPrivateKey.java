package org.fsn_cfc.pakey;

import java.math.BigInteger;

public class PaPrivateKey extends PaPublicKey {


	protected BigInteger d = null;
	
	protected BigInteger dInverse = null;
	
	
	public PaPrivateKey(BigInteger n, BigInteger d, long seed){
		super(n, seed);
		
		if (!(inModNStar(d.mod(n))))
			throw new IllegalArgumentException("d must be relatively prime to n");
		
		this.d = d;
		this.dInverse = this.d.modInverse(ns);
	}
	
	
	public PaPrivateKey(BigInteger p, BigInteger q, BigInteger d, long seed) {
		super(p,q,seed);
		
		if (!(inModNStar(d.mod(n))))
			throw new IllegalArgumentException("d must be relatively prime to n");
		
		BigInteger phin = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		BigInteger lambda = phin.divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
		
		if (!(d.mod(lambda).compareTo(BigInteger.ZERO)==0))
			throw new IllegalArgumentException("d must be a multiple of lcm(p-1,q-1)");
		
		this.d = d;
		this.dInverse = this.d.modInverse(ns);
	}
	
	
	
	public BigInteger getD() {
		return d;
	}
	
	public BigInteger getDInverse() {
		return dInverse;
	}
	
}
