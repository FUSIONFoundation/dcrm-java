package org.fsn_cfc.cmt;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.fsn_cfc.util.RandomUtil;
import org.fsn_cfc.util.OtherUtil;

import uk.ac.ic.doc.jpair.api.Field;
import uk.ac.ic.doc.jpair.api.FieldElement;
import uk.ac.ic.doc.jpair.api.Pairing;
import uk.ac.ic.doc.jpair.pairing.BigInt;
import uk.ac.ic.doc.jpair.pairing.EllipticCurve;
import uk.ac.ic.doc.jpair.pairing.Point;
import uk.ac.ic.doc.jpair.pairing.Predefined;

public class MTDCommitment {

	private final Commitment commitment;
	private final Open<BigInteger> open;

	
	
	private MTDCommitment(Commitment commitment, Open<BigInteger> open) {
		this.commitment = commitment;
		this.open = open;
	}
	
	
	
	public static MTDCommitment multiLinnearCommit(SecureRandom rand, CmtMasterPublicKey mpk, BigInteger... secrets) {
		
		EllipticCurve curve = mpk.pairing.getCurve();
		
		BigInteger e = RandomUtil.randomFromZn(mpk.q, rand);
		BigInteger r = RandomUtil.randomFromZn(mpk.q, rand);
		
		byte[][] secretsBytes = new byte[secrets.length][];
		for (int i = 0; i < secrets.length; i++) {
			secretsBytes[i] = secrets[i].toByteArray();
		}
		
		BigInteger digest = new BigInteger(OtherUtil.sha256Hash(secretsBytes)).mod(mpk.q);
		
		Point he = curve.add(mpk.h, curve.multiply(mpk.g, new BigInt(e)));
		
		Point a = curve.add(curve.multiply(mpk.g, new BigInt(digest)), curve.multiply(he, new BigInt(r)));
		
		Open<BigInteger> open = new Open<BigInteger>(r, secrets);
		
		Commitment commitment = new Commitment(e, a);
		
		return new MTDCommitment(commitment, open);
	}
	

	public static boolean checkcommitment(Commitment commitment, Open<BigInteger> open, CmtMasterPublicKey mpk) {
		
		EllipticCurve curve = mpk.pairing.getCurve();
		
		Point g = mpk.g;
		Point h = mpk.h;
		
		BigInteger[] secrets = open.getSecrets();
		byte[][] secretsBytes = new byte[secrets.length][];
		for (int i = 0; i < secrets.length; i++) {
			secretsBytes[i] = secrets[i].toByteArray();
		}
		
		BigInteger digest = new BigInteger(OtherUtil.sha256Hash(secretsBytes)).mod(mpk.q);
		
		return DDH(curve.multiply(g,new BigInt(open.getRandomness())),
				curve.add(h, curve.multiply(g, new BigInt(commitment.pubkey))),
				curve.add(commitment.committment, curve.multiply(g, new BigInt(digest.negate()))), g,
				mpk.pairing);

	}
	
	static boolean DDH(Point a, Point b, Point c, Point generator, Pairing pairing) 
	{
		return pairing.compute(a, b).equals(pairing.compute(generator, c));
	}

	
	public static CmtMasterPublicKey generateMasterPK() {
		
		Pairing pairing = Predefined.ssTate();

		SecureRandom rnd = new SecureRandom();
		
		EllipticCurve G = pairing.getCurve();
		
		Point g = G.getBasePoint(rnd, pairing.getGroupOrder(), pairing.getCofactor());
		BigInteger q = new BigInteger(pairing.getGroupOrder().toByteArray());
		
		Point h = pairing.RandomPointInG1(rnd);
		
		return new CmtMasterPublicKey(g, q, h, pairing);

	}
	

	
	public Open<BigInteger> cmtOpen(){
		return open;
	}
	
	
	
	
	public Commitment cmtCommitment() {
		return commitment;
	}


}