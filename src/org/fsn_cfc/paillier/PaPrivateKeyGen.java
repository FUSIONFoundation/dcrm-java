package org.fsn_cfc.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;


public class PaPrivateKeyGen {
   
	
	public static PaPrivateKey PaPrivateKeyGen(int s, long seed) {
		
		BigInteger minprm=null;
		BigInteger maxprm=null;
		BigInteger phin=null;
		BigInteger p;
		BigInteger q;
		BigInteger d;
		BigInteger n;
		SecureRandom rnd;
		
		boolean ok=false;
		
		
		rnd= new SecureRandom(BigInteger.valueOf(seed).toByteArray());
		
		do {
			p = PaPrivateKeyGen.getPrime(s, rnd);
			q = PaPrivateKeyGen.getPrime(s, rnd); 
			minprm = q.min(p);
			maxprm = q.max(p);
			
			p = minprm;
			q = maxprm;
			
			if((q.mod(p.subtract(BigInteger.ONE))).compareTo(BigInteger.ZERO)!=0) {
				ok=true;
			}
			
		} while(!ok);
		
		n=p.multiply(q);
		  		
		phin=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		  
		d=phin.divide((p.subtract(BigInteger.ONE)).gcd(q.subtract(BigInteger.ONE)));
		
		return new PaPrivateKey(n, d, seed);
	}

	
	
	public static BigInteger getPrime(int length, Random random) {
		return BigInteger.probablePrime(length, random);
	}
	
}
