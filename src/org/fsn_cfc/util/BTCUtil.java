package org.fsn_cfc.util;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;



public class BTCUtil
{
     

	
	
public static String ConvertPrivKeyToBitcoinConformBase58(String str)
{
	   if(str.equals("")) return "";
	   String msb = "80";                         																										
	   String h = getHashSHA256_from_HexString(msb+str);
	          h = getHashSHA256_from_HexString(h);              																						
	          h = h.substring(0,8);																														
	   return Base58Util.hexStringToBase58(msb + str + h);																									
}
	
	
public static String ConvertPrivKeyToBitcoinConformBase58Compressed(String str)
{
       if(str.equals("")) return "";
   	   String msb = "80";                         																										
	   String com = "01";                         																										
	   String h = getHashSHA256_from_HexString(msb+str+com);
	          h = getHashSHA256_from_HexString(h);               																						
	          h = h.substring(0,8);																														
	  return Base58Util.hexStringToBase58(msb + str + com + h);        																					
}

	
	
public static String ConvertPublicKeyToBitcoinAdress(String str)
{
    String h = getHashSHA256_from_HexString(str);																									
    h = getHashRIPEMD160_from_HexString(h);	
    
    
    String msb = "6F";  																																
	String adr = msb + h;                                             																				
	h   = getHashSHA256_from_HexString(adr);					
	h   = getHashSHA256_from_HexString(h);																										
	adr = adr +  h.substring(0,8);
	
	return Base58Util.hexStringToBase58(adr);																											
}
	
	
    
public static String wuerfelToHexString(String str)                  
{
	BigInteger mod = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);	            
	str = str.replaceAll("-","");								 																						
	str = str.replaceAll("6","0");																																								
      	BigInteger dec = new BigInteger(str,6);																											
      	dec = dec.mod(mod);																																
      	String erg = dec.toString(16);  																													
      	while(erg.length() < 64) erg="0"+erg;																												
      	return erg;
}
	
	

	

// ------------------------------------------------- Hash SHA256 ------------------------------------------------------//
	
public static String getHashSHA256_from_HexString(String str) 
{
  byte[] b = getHashSHA256(Base58Util.hexStringToByteArray(str));
  return Base58Util.byteArrayToHexString(b);
}
	
	
public static String getHashSHA256(String str)
{
  byte[] b = null;
try {
	b = getHashSHA256((str).getBytes("UTF-8"));
} catch (UnsupportedEncodingException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
  return Base58Util.byteArrayToHexString(b);
}
	
	
public static byte[] getHashSHA256(byte[] b) 
{
  MessageDigest sha = null;
try {
	sha = MessageDigest.getInstance("SHA-256");
} catch (NoSuchAlgorithmException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}
  return sha.digest(b);
}
	
	
	
// ------------------------------------------------- Hash RIPEMD-160 ----------------------------------------------------//
		
public static String getHashRIPEMD160_from_HexString(String str)
{
  byte[] b = getHashRIPEMD160(Base58Util.hexStringToByteArray(str));
  return Base58Util.byteArrayToHexString(b);
}
	
	
public static byte[] getHashRIPEMD160(byte[] b)
{
  RIPEMD160Digest ripemd = new RIPEMD160Digest();
  ripemd.update (b, 0, b.length);
  byte[] hash160 = new byte[ripemd.getDigestSize()];
  ripemd.doFinal (hash160, 0);
  return hash160;	
}
	
	
	
// ------------------------------------------------- Public Key ---------------------------------------------------------//	

	
	
public static int getFormat(String str)
{
	if(str.equals(""))   								return 0;																									
	if(str.length()==64 && str.matches("[0-9a-fA-F]+")) return 1;																									
	if(str.length()==51 && str.matches("[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+") && str.charAt(0)=='5') 							return 2;	
	if(str.length()==52 && str.matches("[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+") && (str.charAt(0)=='L' || str.charAt(0)=='K'))	return 3;	
	if(str.length()==44 && str.matches("[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]+") &&  str.charAt(43)=='=') 				return 4;	
	return -1;
}
	
	
	
public static int is_PrivKey_Valid(String str)
{
	if(str.equals("")) str="0";																				
	BigInteger min = new BigInteger("0",16);																
	BigInteger uns = new BigInteger("00000F0000000000000000000000000000000000000000000000000000000000",16);	
	BigInteger max = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",16);	
	BigInteger key = new BigInteger(str,16);
	if(key.compareTo(min) <= 0) return -1; 
	if(key.compareTo(max) >  0) return  1;
	if(key.compareTo(uns) <  0) return  2;
	return 0;
}
	
	
	
public static boolean ist_PrivateKey_Base58_Valid(String str)
{
	if(str.equals("") || str.length() != 51) 		return false;                                            
	String roh = Base58Util.Base58ToHexString(str,74);															
	String a = roh.substring(0,66);																			
	String b = roh.substring(66,74).toUpperCase();															
	String h = null;					
	h = getHashSHA256_from_HexString(a);																
	h = getHashSHA256_from_HexString(h);			
	h=h.substring(0,8); 																					
	if(b.equals(h)) return true;																			
	return false;
}
	
	
	
public static boolean ist_PrivateKey_Base58compressed_Valid(String str)
{
	if(str.equals("") || str.length() != 52) 		return false;                                            
	String roh = Base58Util.Base58ToHexString(str,76);															
	String a = roh.substring(0,68);																			
	String b = roh.substring(68,76).toUpperCase();															
	String h = null;		
	h = getHashSHA256_from_HexString(a);																
	h = getHashSHA256_from_HexString(h);
	h=h.substring(0,8); 																					
	if(b.equals(h)) return true;																			
	return false;
}
	
	
	
public static boolean ist_PrivateKey_Base64_Valid(String str)
{
	if(str.length()==44 && str.matches("[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]+") &&  str.charAt(43)=='=') 		return true;          
	return false;																													
}
		
}