package org.fsn_cfc.cmt;

import java.math.BigInteger;

import uk.ac.ic.doc.jpair.api.Pairing;
import uk.ac.ic.doc.jpair.pairing.Point;


public class CmtMasterPublicKey {

	
	public final Point g;
	public final BigInteger q; 
	public final Point h;
	public final Pairing pairing;
	
	public CmtMasterPublicKey(Point g, BigInteger q, Point h, uk.ac.ic.doc.jpair.api.Pairing pairing) {
		this.g = g;
		this.h = h;
		this.q = q;
		this.pairing = pairing;
	}


}
