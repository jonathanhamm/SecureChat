import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;

import csec2012.AESCipher;
import csec2012.CSec2012Prov;



public class Chat {
	
	public static void main (String[] args)
	{
		CSec2012Prov provider;
		
		provider = new CSec2012Prov();
		Security.insertProviderAt(provider, 1);
		try {
			Cipher.getInstance("AES", provider);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
 