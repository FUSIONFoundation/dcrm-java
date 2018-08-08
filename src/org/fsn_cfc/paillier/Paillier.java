package org.fsn_cfc.paillier;

import java.math.*;

public class Paillier extends AbstractPaillier{

	protected PaPrivateKey privateKey = null;

	
	public Paillier(){}
	
	
	public Paillier(PaPublicKey pubkey) {
		this.publicKey = pubkey;
	}
	
	
	public Paillier(PaPrivateKey prikey) {
		this(prikey.getPublicKey());
		this.privateKey = prikey;
	}

	

	public BigInteger decrypt(BigInteger c)
	{
		BigInteger c1=null;
		
		c1= c.modPow(privateKey.getD(),privateKey.getNSPlusOne());

		return (privateKey.getDInverse().multiply((c1.subtract(BigInteger.ONE)).divide(privateKey.getN()))).mod(privateKey.getN());
	}
	
}

