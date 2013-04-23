import java.security.Security;
import javax.crypto.CipherSpi;
import csec2012.CSec2012Prov;



public class Chat {
	public static void main (String[] args)
	{
		CSec2012Prov provider = new CSec2012Prov();
		Security.insertProviderAt(provider, 1);
	}
}
 