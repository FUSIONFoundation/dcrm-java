package org.fsn_cfc.util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.fsn_cfc.cmt.Commitment;
import org.fsn_cfc.cmt.MTDCommitment;
import org.fsn_cfc.cmt.Open;
import org.fsn_cfc.fusiondcrm.FusionDCRM;
import org.fsn_cfc.zkp.ZkpKG;
import org.fsn_cfc.zkp.ZkpSignOne;
import org.fsn_cfc.zkp.ZkpSignTwo;

public class User {
	
	
	//kgRoundOne
	private BigInteger xShare, xShareRnd, encXShare;
	private ECPoint yShare;
	private MTDCommitment mpkEncXiYi;
	private Open<BigInteger> openEncXiYi;
	private Commitment cmtEncXiYi;
	
	
	//kgRoundTwo
	private ZkpKG zkpKG;
	
	
	//kgRoundThree
	BigInteger encX;
    ECPoint pk;
	
	
	
	
	//Signning round 1
	private BigInteger rhoI, rhoIRnd, uI, vI;
	
	private MTDCommitment mpkUiVi;
	private Open<BigInteger> openUiVi;
	private Commitment cmtUiVi;
	
	
	
	//Signning round 2
	private ZkpSignOne zkp1;
	
	
	
	//Signning round 3	
	private BigInteger kI, cI, cIRnd;
	private ECPoint rI;

	private BigInteger mask, wI;
	
	private MTDCommitment mpkRiWi;
	private Open<BigInteger> openRiWi;
	private Commitment cmtRiWi;
	
	
	
	//Signning round 4
	private ZkpSignTwo zkp_i2;
	
	
	
	
	public BigInteger getxShare() {
		return xShare;
	}
	public void setxShare(BigInteger xShare) {
		this.xShare = xShare;
	}
	public BigInteger getxShareRnd() {
		return xShareRnd;
	}
	public void setxShareRnd(BigInteger xShareRnd) {
		this.xShareRnd = xShareRnd;
	}
	public BigInteger getRhoI() {
		return rhoI;
	}
	public void setRhoI(BigInteger rhoI) {
		this.rhoI = rhoI;
	}
	public BigInteger getRhoIRnd() {
		return rhoIRnd;
	}
	public void setRhoIRnd(BigInteger rhoIRnd) {
		this.rhoIRnd = rhoIRnd;
	}
	public Open<BigInteger> getOpenUiVi() {
		return openUiVi;
	}
	public void setOpenUiVi(Open<BigInteger> openUiVi) {
		this.openUiVi = openUiVi;
	}
	public Open<BigInteger> getOpenRiWi() {
		return openRiWi;
	}
	public void setOpenRiWi(Open<BigInteger> openRiWi) {
		this.openRiWi = openRiWi;
	}
	public BigInteger getkI() {
		return kI;
	}
	public void setkI(BigInteger kI) {
		this.kI = kI;
	}
	public BigInteger getcI() {
		return cI;
	}
	public void setcI(BigInteger cI) {
		this.cI = cI;
	}
	public BigInteger getcIRnd() {
		return cIRnd;
	}
	public void setcIRnd(BigInteger cIRnd) {
		this.cIRnd = cIRnd;
	}
	public BigInteger getuI() {
		return uI;
	}
	public void setuI(BigInteger uI) {
		this.uI = uI;
	}
	public BigInteger getvI() {
		return vI;
	}
	public void setvI(BigInteger vI) {
		this.vI = vI;
	}
	public BigInteger getwI() {
		return wI;
	}
	public void setwI(BigInteger wI) {
		this.wI = wI;
	}
	public BigInteger getEncXShare() {
		return encXShare;
	}
	public void setEncXShare(BigInteger encXShare) {
		this.encXShare = encXShare;
	}
	public ECPoint getyShare() {
		return yShare;
	}
	public void setyShare(ECPoint yShare) {
		this.yShare = yShare;
	}
	public MTDCommitment getMpkUiVi() {
		return mpkUiVi;
	}
	public void setMpkUiVi(MTDCommitment mpkUiVi) {
		this.mpkUiVi = mpkUiVi;
	}
	public Commitment getCmtUiVi() {
		return cmtUiVi;
	}
	public void setCmtUiVi(Commitment cmtUiVi) {
		this.cmtUiVi = cmtUiVi;
	}
	public ZkpSignOne getZkp1() {
		return zkp1;
	}
	public void setZkp1(ZkpSignOne zkp1) {
		this.zkp1 = zkp1;
	}
	public ECPoint getrI() {
		return rI;
	}
	public void setrI(ECPoint rI) {
		this.rI = rI;
	}
	public BigInteger getMask() {
		return mask;
	}
	public void setMask(BigInteger mask) {
		this.mask = mask;
	}
	public MTDCommitment getMpkRiWi() {
		return mpkRiWi;
	}
	public void setMpkRiWi(MTDCommitment mpkRiWi) {
		this.mpkRiWi = mpkRiWi;
	}
	public Commitment getCmtRiWi() {
		return cmtRiWi;
	}
	public void setCmtRiWi(Commitment cmtRiWi) {
		this.cmtRiWi = cmtRiWi;
	}
	public ZkpSignTwo getZkp_i2() {
		return zkp_i2;
	}
	public void setZkp_i2(ZkpSignTwo zkp_i2) {
		this.zkp_i2 = zkp_i2;
	}
	public MTDCommitment getMpkEncXiYi() {
		return mpkEncXiYi;
	}
	public void setMpkEncXiYi(MTDCommitment mpkEncXiYi) {
		this.mpkEncXiYi = mpkEncXiYi;
	}
	public Open<BigInteger> getOpenEncXiYi() {
		return openEncXiYi;
	}
	public void setOpenEncXiYi(Open<BigInteger> openEncXiYi) {
		this.openEncXiYi = openEncXiYi;
	}
	public Commitment getCmtEncXiYi() {
		return cmtEncXiYi;
	}
	public void setCmtEncXiYi(Commitment cmtEncXiYi) {
		this.cmtEncXiYi = cmtEncXiYi;
	}
	public ZkpKG getZkpKG() {
		return zkpKG;
	}
	public void setZkpKG(ZkpKG zkpKG) {
		this.zkpKG = zkpKG;
	}
	public BigInteger getEncX() {
		return encX;
	}
	public void setEncX(BigInteger encX) {
		this.encX = encX;
	}
	public ECPoint getPk() {
		return pk;
	}
	public void setPk(ECPoint pk) {
		this.pk = pk;
	}
	
}
