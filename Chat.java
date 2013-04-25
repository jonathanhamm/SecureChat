import java.security.AlgorithmParameterGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;

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
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.Scanner;

public class Chat {
	public static CSec2012Prov provider = new CSec2012Prov();
	public static void main(String[] args) {
		Security.insertProviderAt(provider, 1);
		try {
			Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		parseArgs(new ArrayDeque<String>(Arrays.asList(args)));
		Socket c = null;
		if (mode == SERVER) {
			try {
				ServerSocket s = new ServerSocket(port);
				c = s.accept();				
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
			} catch (IOException e) {
				System.err.println("There was an error connecting:");
				System.err.println(e);
				System.exit(-3);
			} catch (SecurityException e) {
				System.err.println("You are not allowed to connect:");
				System.err.println(e);
				System.exit(-2);
			}
		} else {
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
	
	public static byte getMode () {
		return mode;
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
}

class ChatSender implements Runnable {
	public ChatSender(InputStream screen, OutputStream conn) {
		this.screen = new Scanner(screen);
		this.conn = new PrintStream(conn);
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", Chat.provider);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//keyagree.generateSecret();
		if (paramgen == null) {
			try {
				paramgen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		try {
			keyagree = KeyAgreement.getInstance("DiffieHellman", "SunJCE");
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} 

		paramgen.init(1024);
		try {
			conn.write(paramgen.generateParameters().getEncoded());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	public void run() {
		while (true) {
			String line = screen.nextLine();
			conn.println(line);
		}
	}
	private static Key key;
	private static KeyAgreement keyagree;
	private static AlgorithmParameterGenerator paramgen = null;
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
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void run() {
		byte[] b = new byte[1024];
		while (true) {
			try {
				int len = conn.read(b);
				if (len == -1) break;
				screen.write(b, 0, len);
			} catch (IOException e) {
				System.err.println("There was an error receiving data:");
				System.err.println(e);
			}
		}
	}
	private Cipher cipher;
	private InputStream conn;
	private OutputStream screen;
}
