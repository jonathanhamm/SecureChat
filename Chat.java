import java.security.Security;



public class Chat {

	public static void main (String[] args)
	{
		Security.insertProviderAt(null, 1);
	}
}
 