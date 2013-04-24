
package csec2012;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher extends CipherSpi {
    byte[] iv;
    byte[] buffer;
    int buffered;
    boolean do_pad;
    boolean do_cbc;
    int opmode;
    AES aes;

    protected void engineSetMode(String mode)
      throws NoSuchAlgorithmException {
    	if (mode.equals("CBC")) {
    		do_cbc = true;
    	} else if (mode.equals("ECB")) {
    		do_cbc = false;
    	} else {
    		throw new NoSuchAlgorithmException();
    	}
    }
    protected void engineSetPadding(String padding)
      throws NoSuchPaddingException {
    	if (padding.equals("NoPadding")) {
	    	do_pad = false;
		} else if (padding.equals("PKCS5Padding")) {
	    	do_pad = true;
		} else {
	    	throw new NoSuchPaddingException();
		}
    }
    protected int engineGetBlockSize() {
    	return 16; // This is constant for AES.
    }
    protected int engineGetOutputSize(int inputLen) {
	/**
	 * Implement me.
	 */
	int total = inputLen + buffered;
    	
    	// No padding, just return total
    	if(do_pad = false)
    		return total;
    	
    	// Padding, calculate padding + total
    	// This is probably wrong -----------
    	if(total % engineGetBlockSize() == 0)
    		return total + engineGetBlockSize();
    	else 
    		return total + (engineGetBlockSize() - (total % engineGetBlockSize()));
    	// ----------------------------------
    }
    protected byte[] engineGetIV() {
    	byte[] retiv = new byte[16];
		System.arraycopy(iv, 0, retiv, 0, 16);
		return retiv;
    }
    protected AlgorithmParameters engineGetParameters() {
	AlgorithmParameters ap = null;
		try {
	    	ap = AlgorithmParameters.getInstance("AES");
	    	ap.init(new IvParameterSpec(engineGetIV()));
		} catch (NoSuchAlgorithmException e) {
	    	System.err.println("Internal Error: " + e);
		} catch (InvalidParameterSpecException e) {
			System.err.println("Internal Error: " + e);
		}
		return ap;
    }
    protected void engineInit(int opmode, Key key, SecureRandom random)
     throws InvalidKeyException {
    	try {
    		engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    	} catch (InvalidAlgorithmParameterException e) {
    		System.err.println("Internal Error: " + e);
    	}
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException {
    	try {
    		engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
    	} catch (InvalidParameterSpecException e) {
    		System.err.println("Internal Error: " + e);
    	} catch (InvalidAlgorithmParameterException e) {
    		System.err.println("Internal Error: " + e);
    	}
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
	/**
	 * Implement me.
	 */
    	this.iv = new byte[engineGetBlockSize()];
    	this.buffer = new byte[engineGetBlockSize()];
    	this.opmode = opmode;
    	this.buffered = 0;
    	random.setSeed(iv);
    	aes = new AES(key.getEncoded());
    }
    private int allocateSize(int inputLen) {
	/**
	 * Implement me.
	 */
    	return 0;
    }
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    	byte[] output = new byte[allocateSize(inputLen)];
    	int size = 0;
    	try {
    		size = engineUpdate(input, inputOffset, inputLen, output, 0);
    	} catch (ShortBufferException e) {
    		System.err.println("Internal Error: " + e);
    	}
    	
    	return Arrays.copyOf(output, size);
    }
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
	/**
	 * Implement me.
	 */
    	int nBytes;
    	int nBlocks = (buffered + inputLen) / engineGetBlockSize();
    	byte[] tmp;
    	while (true) {
    		if (nBlocks == 0) {
    			nBytes = inputLen % engineGetBlockSize();
    			for (int i = 0; i < nBytes; i++)
    				buffer[buffered + i] = input[inputOffset + i];
    			buffered += nBytes;
    			return 0;
    		}
    		else {
    			tmp = new byte[engineGetBlockSize()];
    			for (int i = 0; buffered < engineGetBlockSize(); buffered++, i++)
    				buffer[buffered] = input[inputOffset + i];
    			if (do_cbc) {
    				for (int i = 0; i < engineGetBlockSize(); i++)
    					buffer[i] ^= iv[i];
    			}
    			tmp = aes.encrypt(buffer);
    			if (do_cbc) {
    				for (int i = 0; i < engineGetBlockSize(); i++)
    					iv[i] = tmp[i];
    			}
    			for (int i = 0; i < engineGetBlockSize(); i++)
    				output[outputOffset + i] = tmp[i];
    			buffered = 0;
    			nBlocks--;
    		}
    	}
    	/*int nPadding;
    	int blockLen = engineGetBlockSize();
    	int nBlocks = inputLen / blockLen;
    	byte[] tmp = new byte[blockLen];
    	
    	if (inputLen % blockLen != 0 || (do_pad && inputLen % blockLen == 0))
    		nBlocks++;
    	for (int i = 0; i < nBlocks; i++) {
    		int j;
    		for (j = 0; j < blockLen; j++) {
    			tmp[j] = input[inputOffset + j];
    			if (do_cbc)
    				tmp[j] ^= iv[j];
    		}
    		if (i == nBlocks-1) {
    			nPadding = blockLen - (inputLen % blockLen);
    			if (do_pad) {				
    				for (; j < nPadding; j++)
    					tmp[j] = (byte)nPadding;
    			} 
    			else {
    				//Zero remaining bytes without PCKS5 Padding ?
    				if (nPadding < 16)
    				for (; j < nPadding; j++)
    					tmp[j] = '\0';
    			}
    		}
    		tmp = aes.encrypt(tmp);
    		for (j = 0; j < blockLen; j++) {
    			output[outputOffset + j] = tmp[j];
    			if (do_cbc)
    				iv[j] = tmp[j];
    		}
    		inputOffset += blockLen;
    		outputOffset += blockLen;
    	}
    	buffered += nBlocks * blockLen; //?*/
    	return 0;
    }
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    	try {
    		byte[] temp = new byte[engineGetOutputSize(inputLen)];
    		int len = engineDoFinal(input, inputOffset, inputLen, temp, 0);
    		return Arrays.copyOf(temp, len);
    	} catch (ShortBufferException e) {
    		System.err.println("Internal Error: " + e);
    		return null;
    	}
    }
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
	/**
	 * Implement me.
	 */
    	return 0;
    }
}
