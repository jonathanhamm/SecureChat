
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
import javax.crypto.Cipher;
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
    boolean encrypt;
    
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
    	if(do_pad == false)
    		return total;
    	
    	// Padding, calculate padding + total
    	// This is probably wrong -----------
    	if(total % engineGetBlockSize() == 0)
    		return total + engineGetBlockSize();
    	else 
    		return total + (engineGetBlockSize() - (total % engineGetBlockSize()));
    		
    	// ---------------------------------- */
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
    	aes = new AES(key.getEncoded());
    	if (opmode == Cipher.ENCRYPT_MODE)
    		encrypt = true;
    	else
    		encrypt = false;
    	if (params == null)
        	random.setSeed(iv);
    	else {
    		/* questionable */
    		iv = ((IvParameterSpec)params).getIV();
    	}

    }
    private int allocateSize(int inputLen) {
	/**
	 * Implement me.
	 */
    	
    	return (inputLen % engineGetBlockSize() == 0) ? inputLen+engineGetBlockSize() : 
    			inputLen + (engineGetBlockSize() - (inputLen % engineGetBlockSize()));
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
    	int i, processed = 0, outputwritten = 0;
    	byte[] tmp;
    	byte[] ivbackup = new byte[engineGetBlockSize()];
    	
    	while (true) {
    		for (i = 0; processed < inputLen && buffered < engineGetBlockSize(); buffered++, i++, processed++) 
    			buffer[buffered] = input[inputOffset + processed];
    		if (!do_pad) {
    			if (processed == inputLen)
    				return outputwritten;
    		}
    		if (processed < inputLen || (processed == inputLen && buffered == engineGetBlockSize() && do_pad && encrypt)) {
    			if (encrypt) {
    				if (do_cbc) {
    					for (int j = 0; j < engineGetBlockSize(); j++)
    						buffer[j] ^= iv[j];
    				}
    				tmp = aes.encrypt(buffer);
    				if (do_cbc) {
    					for (int j = 0; j < engineGetBlockSize(); j++) 
    						iv[j] = tmp[j];
    				}
    			}
    			else {
    				for (int j = 0; j < engineGetBlockSize(); j++) {
    					ivbackup[j] = iv[j];
    					iv[j] = buffer[j];
    				}
    				tmp = aes.decrypt(buffer);
    				if (do_cbc) {
    					for (int j = 0; j < engineGetBlockSize(); j++)
    						tmp[j] ^= ivbackup[j];
    				}
    			}
    			if (output.length < outputOffset + engineGetBlockSize())
    				throw new ShortBufferException();
				for (int j = 0; j < engineGetBlockSize(); j++, outputwritten++)
					output[outputOffset + outputwritten] = tmp[j];
				buffered = 0;
    		}
    		else 
    			return outputwritten;
    	}
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
    	int outputwritten;
    	byte padding;
    	byte[] tmp;
    	byte[] ivbackup = new byte[engineGetBlockSize()];
    	
    	if (buffered + inputLen % engineGetBlockSize() != 0 && !do_pad)
    		throw new IllegalBlockSizeException();
    	outputwritten = engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    	if (encrypt) {
    		if (do_pad) {
    			padding = (byte) (engineGetBlockSize() - buffered);
    			for (int i = buffered; i < engineGetBlockSize(); i++, buffered++)
    				buffer[i] = padding;
    		}
    		if (do_cbc) {
    			for (int i = 0; i < engineGetBlockSize(); i++)
    				buffer[i] ^= iv[i];
    		}
    		tmp = aes.encrypt(buffer);
    		if (do_cbc) {
    			for (int i = 0; i < engineGetBlockSize(); i++)
    				iv[i] = tmp[i];
    		}
    	}
    	else {
    		if (do_cbc) {
    			for (int i = 0; i < engineGetBlockSize(); i++) {
    				ivbackup[i] = iv[i];
    				iv[i] = buffer[i];
    			}
    		}
    		tmp = aes.decrypt(buffer);
    		if (do_cbc) {
				for (int j = 0; j < engineGetBlockSize(); j++)
					tmp[j] ^= ivbackup[j];
    		}
    		if (do_pad) {
    			padding = tmp[engineGetBlockSize() - 1];
    			if (padding <= 0 || padding > engineGetBlockSize())
    				throw new BadPaddingException();
    			for (int i = 0, j = engineGetBlockSize()-1; i < padding; i++, j--)
    					tmp[j] = 0;
    		}
    	}
    	if (output.length < outputOffset + engineGetBlockSize())
    		throw new ShortBufferException();
		for (int i = 0; i < engineGetBlockSize(); i++, outputwritten++)
			output[outputOffset + outputwritten] = tmp[i];
		buffered = 0;
    	return outputwritten;
    }
	public static void printByteArray (byte[] array) {
		for (int i = 0; i < array.length; i++)
			System.out.printf("0x%02x,", array[i]);
		System.out.println();
	}

}
