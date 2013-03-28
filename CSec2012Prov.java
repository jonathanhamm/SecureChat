
package csec2012;

import java.security.Provider;

/**
 * A Provider that links the AES cipher from Project 1 into the JCE
 */
public class CSec2012Prov extends Provider {
    /**
     * Constructor.
     *
     * Use this with java.security.Security.insertProviderAt() to install this
     * provider into your Chat project.
     */
    public CSec2012Prov() {
        super("CSec2012", 1.0, "Provider for AES from Project 1.");

        put("Cipher.AES", "csec2011.AESCipher");
    }
}
