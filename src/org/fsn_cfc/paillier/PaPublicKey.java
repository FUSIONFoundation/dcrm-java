package org.fsn_cfc.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaPublicKey{
	
	protected BigInteger n=null;
	
	protected BigInteger ns=null;
	
	protected BigInteger nSPlusOne=null;
	
	protected BigInteger nPlusOne=null;
	
	protected SecureRandom rnd=null;
	
	
	
	
	
	public PaPublicKey(BigInteger n, SecureRandom rnd) {

		
		this.n = n;
		this.ns = n;
		this.nSPlusOne = this.n.multiply(this.n);
		this.nPlusOne = this.n.add(BigInteger.ONE);
		this.rnd = rnd;
	}
	
	
	public PaPublicKey(BigInteger n, long seed)
	{
		 this(n, new SecureRandom(BigInteger.valueOf(seed).toByteArray()));
	}
	
	
	public PaPublicKey(BigInteger p, BigInteger q, long seed) {
		this(p.multiply(p), seed);
		
		if (p.compareTo(q) == 0)
			throw new IllegalArgumentException("p and q must be different primes");
	}
	
	public PaPublicKey(byte[] b, long seed) {
		this(new BigInteger(b), seed);
	}
	
	
	
	
	
	
	
	
	public BigInteger getRandomModN() {
		BigInteger r;
		do {
			r = new BigInteger(n.bitLength(),rnd);
		} while (r.compareTo(n)>=0);
		return r;
	}
	
	public BigInteger getRandomModNStar() {
		BigInteger r;
		do {
			r = new BigInteger(n.bitLength(),rnd);
		} while (!inModNStar(r, n));
		return r;
	}

	public BigInteger getRandomModNSPlusOneStar() {
		BigInteger r;
		do {
			r = new BigInteger(nSPlusOne.bitLength(),rnd);
		} while (!inModNStar(r, nSPlusOne));
		return r;
	}
	
	

	
	
	
	
	
	
	
	
	
	public static boolean inModN(BigInteger a, BigInteger n) {
		return (a.compareTo(n) < 0 && a.compareTo(BigInteger.ZERO) >= 0);
	}
	
	public static boolean inModNStar(BigInteger a, BigInteger n) {
		return (a.gcd(n).equals(BigInteger.ONE) && inModN(a, n));
	}
	
	
	public boolean inModNStar(BigInteger a) {
		return inModNStar(a, n);
	}
	
	public boolean inModNSPlusOneStar(BigInteger a) {
		return inModNStar(a, nSPlusOne);
	}
	
	public boolean inModN(BigInteger a) {
		return inModN(a, n);
	}
	
	public boolean inModNS(BigInteger a) {
		return inModN(a, ns);
	}
	
	public boolean inModNSPlusOne(BigInteger a) {
		return inModN(a, nSPlusOne);
	}
	
	public byte[] toByteArray() {
		
		int size = n.toByteArray().length;
		byte[] r = new byte[size];
		System.arraycopy(n.toByteArray(), 0, r, 4, size);
		
		return r;
	}
	

	public PaPublicKey getPublicKey() {
		return new PaPublicKey(n, rnd.nextLong());
	}
	
	public boolean canEncrypt() {
		return false;
	}

	public BigInteger getN() {
		return n;
	}

	public BigInteger getNS() {
		return ns;
	}
	
	public BigInteger getNSPlusOne() {
		return nSPlusOne;
	}

	public BigInteger getNPlusOne() {
		return nPlusOne;
	}

	public SecureRandom getRnd() {
		return rnd;
	}
	
	public void updateRnd() {
		setRnd(rnd.nextLong());
	}
	
	public void setRnd(long seed) {
		setRnd(new SecureRandom(BigInteger.valueOf(seed).toByteArray()));
	}
	
	public void setRnd(SecureRandom rnd) {
		this.rnd = rnd;
	}
	
}
