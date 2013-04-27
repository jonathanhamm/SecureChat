import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import csec2012.AESCipher;
import csec2012.CSec2012Prov;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Scanner;

public class Chat {
	public static CSec2012Prov provider = new CSec2012Prov();
	public static void main(String[] args) {
		Security.insertProviderAt(provider, 1);
		parseArgs(new ArrayDeque<String>(Arrays.asList(args)));
		Socket c = null;
		if (mode == SERVER) {
			try {
				ServerSocket s = new ServerSocket(port);
				c = s.accept();	
				shared = getSharedServer(s, c);
			} catch (IOException e) {
				System.err.println("There was an error opening the server:");
				System.err.println(e);
				System.exit(-3);
			} catch (SecurityException e) {
				System.err.println("You are not allowed to open the server:");
				System.err.println(e);
				System.exit(-2);
			}
		} else if (mode == CLIENT) {
			try {
				c = new Socket(addr, port);
				shared = getSharedClient(c);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		 else {
			System.err.println("Please specify the mode.");
			printUsage();
			System.exit(-1);
		}
		try {
			new Thread(new ChatSender(System.in, c.getOutputStream())).start();
			new Thread(new ChatReceiver(c.getInputStream(), System.out)).start();
		} catch (IOException e) {
			System.err.println("There was an error setting up data transfer:");
			System.err.println(e);
			System.exit(-3);
		}
	}
	private static void parseArgs(Queue<String> args) {
		while (args.peek() != null) {
			String opt = args.poll();
			if (opt.equals("-s")) {
				if (mode != UNSPECIFIED) {
					printUsage();
					System.exit(-1);
				}
				mode = SERVER;
				parsePort(args);
			} else if (opt.equals("-c")) {
				if (mode != UNSPECIFIED) {
					printUsage();
					System.exit(-1);
				}
				mode = CLIENT;
				parseAddr(args);
				parsePort(args);
			}
		}
	}
	private static void badPort() {
		System.err.println("Please specify a port between 1 and 65535.");
		printUsage();
		System.exit(-1);
	}
	private static void parsePort(Queue<String> args) {
		String strPort = args.poll();
		if (strPort == null) {
			badPort();
		}
		try {
			port = Integer.parseInt(strPort);
		} catch (NumberFormatException e) {
			badPort();
		}
		if (!(1 <= port && port <= 65535)) {
			badPort();
		}
	}
	private static void badAddr() {
		System.err.println("Please specify an IP address or host name.");
		printUsage();
		System.exit(-1);
	}
	private static void parseAddr(Queue<String> args) {
		String hostname = args.poll();
		if (hostname == null) {
			badAddr();
		}
		try {
			addr = InetAddress.getByName(hostname);
		} catch (UnknownHostException e) {
			System.err.println("The address '" + hostname + "' is unrecognized or could not be resolved.");
			badAddr();
		} catch (SecurityException e) {
			System.err.println("You are not allowed to resolve '" + hostname + "'.");
			System.exit(-2);
		}
	}
	private static void printUsage() {
		System.err.println("Usage:");
		System.err.println("    java Chat -s PORT");
		System.err.println("    invokes Chat in server mode attempting to listen on PORT.");
		System.err.println("");
		System.err.println("    java Chat -c ADDRESS PORT");
		System.err.println("    invokes Chat in client mode attempting to connect to ADDRESS on PORT.");
	}
	
	private static byte[] getSharedClient (Socket c) {
		int size;
		byte[] size_b = new byte[4];
		byte[] dparam, pubkey;

		try {
			c.getInputStream().read(size_b, 0, 4);
			size = byteArrayToI(size_b);
			dparam = new byte[size];
			c.getInputStream().read(dparam, 0, size);
			aparam = AlgorithmParameters.getInstance("DiffieHellman");
			aparam.init(dparam);
			dhparam = aparam.getParameterSpec(DHParameterSpec.class);
			keypairgen = KeyPairGenerator.getInstance("DiffieHellman");
			keypairgen.initialize(dhparam);
			keypair = keypairgen.generateKeyPair();
			pubkey = keypair.getPublic().getEncoded();
			c.getOutputStream().write(iToByteArray(pubkey.length), 0 ,4);
			c.getOutputStream().write(pubkey, 0, pubkey.length);
			c.getInputStream().read(size_b, 0, 4);
			size = byteArrayToI(size_b);
			pubkey = new byte[size];
			c.getInputStream().read(pubkey, 0, size);
			x509spec = new X509EncodedKeySpec(pubkey);
			keyfactory = KeyFactory.getInstance("DiffieHellman");
			publickey = keyfactory.generatePublic(x509spec);
			keyagree = KeyAgreement.getInstance("DiffieHellman", "SunJCE");
			keyagree.init(keypair.getPrivate());
			keyagree.doPhase(publickey, true);
			return keyagree.generateSecret("aes").getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	private static byte[] getSharedServer (ServerSocket s, Socket c) {
		int size;
		byte[] size_b = new byte[4];
		byte[] dparam, pubkey;

		try {
			paramgen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
			paramgen.init(1024);
			dparam = paramgen.generateParameters().getEncoded();
			aparam = AlgorithmParameters.getInstance("DiffieHellman");
			aparam.init(dparam);
			dhparam = aparam.getParameterSpec(DHParameterSpec.class);
			keypairgen = KeyPairGenerator.getInstance("DiffieHellman");
			keypairgen.initialize(dhparam);
			keypair = keypairgen.generateKeyPair();
			c.getOutputStream().write(iToByteArray(dparam.length), 0 ,4);
			c.getOutputStream().write(dparam, 0, dparam.length);
			pubkey = keypair.getPublic().getEncoded();
			c.getOutputStream().write(iToByteArray(pubkey.length), 0 ,4);
			c.getOutputStream().write(pubkey, 0, pubkey.length);
			c.getInputStream().read(size_b, 0, 4);
			size = byteArrayToI(size_b);
			pubkey = new byte[size];
			c.getInputStream().read(pubkey, 0, size);
			x509spec = new X509EncodedKeySpec(pubkey);
			keyfactory = KeyFactory.getInstance("DiffieHellman");
			publickey = keyfactory.generatePublic(x509spec);
			keyagree = KeyAgreement.getInstance("DiffieHellman", "SunJCE");
			keyagree.init(keypair.getPrivate());
			keyagree.doPhase(publickey, true);
			return keyagree.generateSecret("aes").getEncoded();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	public static byte getMode () {
		return mode;
	}
	public static SecretKeySpec getAESKey () {
		byte[] tmp = new byte[16];
		
		for (int i = 0; i < 16; i++)
			tmp[i] = shared[i];
		return new SecretKeySpec(tmp, "AES/CBC/PKCS5Padding");
	}
	public static IvParameterSpec getIV () {
		byte[] tmp = new byte[16];
		
		for (int i = 0; i < 16; i++)
			tmp[i] = shared[i];
		return new IvParameterSpec(tmp);
	}
	private static byte[] iToByteArray (int i) {
		return ByteBuffer.allocate(4).putInt(i).array();
	}
	private static int byteArrayToI (byte[] array) {
	    return   array[3] & 0xFF | (array[2] & 0xFF) << 8 |
        		(array[1] & 0xFF) << 16 | (array[0] & 0xFF) << 24;
	}
	public static void printByteArray (byte[] array) {
		for (int i = 0; i < array.length; i++)
			System.out.printf("0x%02x,", array[i]);
		System.out.println();
	}
	
	private static final byte UNSPECIFIED = 0;
	private static final byte SERVER = 1;
	private static final byte CLIENT = 2;
	
	private static byte mode = UNSPECIFIED;
	private static InetAddress addr = null;
	private static int port = 0;
	
	private static byte[] shared;
	
	private static DHParameterSpec dhparam;
	private static AlgorithmParameters aparam;
	private static AlgorithmParameterGenerator paramgen = null;
	private static KeyPairGenerator keypairgen;
	private static KeyPair keypair;
	private static KeyAgreement keyagree;
	private static KeyFactory keyfactory;
	private static PublicKey publickey;
	private static X509EncodedKeySpec x509spec;
}

class ChatSender implements Runnable {
	public ChatSender(InputStream screen, OutputStream conn) {
		this.screen = new Scanner(screen);
		this.conn = new PrintStream(conn);
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", Chat.provider);
			cipher.init(Cipher.ENCRYPT_MODE, Chat.getAESKey(), Chat.getIV());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void run() {
		byte[] buffer = new byte[16];
		byte[] encrypted = new byte[16];
		
		while (true) {
			String line = screen.nextLine();
			buffer = line.getBytes();
			try {
				encrypted = cipher.doFinal(buffer);
				for (int i = 0; i < buffer.length; i++)
					buffer[i] = 0;
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			conn.write(encrypted, 0, encrypted.length);
		}
	}
	private Scanner screen;
	private PrintStream conn;
	private Cipher cipher;
}

class ChatReceiver implements Runnable {
	public ChatReceiver(InputStream conn, OutputStream screen) {
		this.conn = conn;
		this.screen = screen;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", Chat.provider);
			cipher.init(Cipher.DECRYPT_MODE, Chat.getAESKey(), Chat.getIV());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void run() {
		byte[] b = new byte[16];
		byte[] decrypted;
		while (true) {
			try {
				for (int i = 0; i < b.length; i++)
					b[i] = 0;
				int len = conn.read(b);
				
				if (len == -1) break;				
				decrypted = cipher.doFinal(b);
				screen.write(decrypted, 0, len);
			} catch (IOException e) {
				System.err.println("There was an error receiving data:");
				System.err.println(e);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		//System.out.println(new String(decrypted));
	}
	private Cipher cipher;
	private InputStream conn;
	private OutputStream screen;
}
