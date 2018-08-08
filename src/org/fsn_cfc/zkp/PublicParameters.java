package org.fsn_cfc.zkp;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.fsn_cfc.paillier.PaPublicKey;

public class PublicParameters{
	
	public final byte[] gRaw;
	public final BigInteger h1;
	public final BigInteger h2;
	public final BigInteger nTilde;
	public final PaPublicKey paillierPubKey;

	public PublicParameters(ECDomainParameters CURVE, BigInteger nTilde, int kPrime, BigInteger h1, BigInteger h2, PaPublicKey paillierPubKey) 
	{
		gRaw = CURVE.getG().getEncoded();
		this.nTilde = nTilde;
		this.h1 = h1;
		this.h2 = h2;
		this.paillierPubKey = paillierPubKey;
	}

	public ECPoint getG(ECDomainParameters curve) {
		return curve.getCurve().decodePoint(gRaw);
	}
}
