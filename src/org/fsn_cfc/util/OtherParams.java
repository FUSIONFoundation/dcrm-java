package org.fsn_cfc.util;

import java.security.SecureRandom;

import org.fsn_cfc.cmt.MTDCommitment;
import org.fsn_cfc.paillier.PaPrivateKey;
import org.fsn_cfc.paillier.PaPrivateKeyGen;
import org.fsn_cfc.paillier.PaPublicKey;
import org.fsn_cfc.paillier.Paillier;
import org.fsn_cfc.cmt.CmtMasterPublicKey;
import org.fsn_cfc.zkp.PublicParameters;

public class OtherParams {
	
	

	//secure random
	public static final SecureRandom SecureRnd;
	
	
	//paillier
	public static final PaPrivateKey PaillPrivKey;
	public static final PaPublicKey PaillPubKey;
	
	public static final Paillier PaillEnc;	
	public static final Paillier PaillDec;
	
	public static final PublicParameters ZKParams;
	
	
	//commitment
	public static final CmtMasterPublicKey MPK;

	static {

		//secure random
		SecureRnd = new SecureRandom();

		
		//paillier
		PaillPrivKey = PaPrivateKeyGen.PaPrivateKeyGen(1024 , SecureRnd.nextLong());
		PaillPubKey = PaillPrivKey.getPublicKey();
		
		PaillEnc = new Paillier(PaillPrivKey.getPublicKey());
		PaillDec = new Paillier(PaillPrivKey);
		
		
		//zk
		ZKParams = OtherUtil.generatePublicParams(BitcoinParams.CURVE, 256, 512, SecureRnd, PaillPubKey.getPublicKey());

		
		//commitment
		MPK = MTDCommitment.generateMasterPK();
		
	}

}
