package org.fsn_cfc.util;

import org.toilelibre.libe.curl.Curl;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class BTCAPIUtil {

	public static String[] getUtxoByAddress(String fromAddress) {
		
		String rlt = Curl.$("https://api.blockcypher.com/v1/btc/test3/addrs/" + fromAddress);
		
		JSONObject rltJson =JSONObject.fromObject(rlt);

		if(rltJson.get("address")==null) {
			return new String[] {"address_error"};
		}else if(rltJson.get("balance").toString().equals("0")) {
			if(!rltJson.get("unconfirmed_balance").toString().equals("0")) {
				return new String[] {"wait_confirm"};
			}
			return new String[] {"no_money"};
		}
		
		JSONArray utxos = rltJson.getJSONArray("txrefs"); 
		
		JSONObject item = null; 
		
		for(int i=0; i<utxos.size(); i++) {
			item = utxos.getJSONObject(i);
			
			if(item.get("tx_input_n").toString().equals("-1") && item.get("spent").toString().equals("false")) {
				return new String[] {item.get("tx_hash").toString(),item.get("tx_output_n").toString(),item.get("value").toString()};
			}
		}
		
		return new String[] {"sys_error"};
	}

}
