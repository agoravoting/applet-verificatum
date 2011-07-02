package org.agora.verificatum;

import java.applet.Applet;
import java.util.Arrays;

import verificatum.arithm.ModPGroup;
import verificatum.arithm.PGroup;
import verificatum.arithm.PGroupElement;
import verificatum.arithm.PGroupElementArray;
import verificatum.arithm.PPGroup;
import verificatum.arithm.PPGroupElement;
import verificatum.arithm.PRing;
import verificatum.arithm.PRingElementArray;
import verificatum.crypto.CryptoKeyGen;
import verificatum.crypto.CryptoKeyGenCramerShoup;
import verificatum.crypto.CryptoKeyPair;
import verificatum.crypto.Hashfunction;
import verificatum.crypto.HashfunctionHeuristic;
import verificatum.crypto.PRG;
import verificatum.crypto.PRGHeuristic;
import verificatum.crypto.RandomSource;
import verificatum.protocol.mixnet.MixNetElGamalInterface;
//import verificatum.test.TestParameters;
//import verificatum.crypto.*;
public class AppletVerificatum extends Applet {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -1423669527827145571L;
//	private String parameter1;
	//private LargeInteger prueba;
//	private boolean exito;
	private String textoCifrado;
    protected static PGroup pGroup;
    protected static RandomSource rs;
    protected static Hashfunction crhf;

    protected static String interfaceName = "native";
    protected static String publicKeyString = "00000000020000000002010000001a766572696669636174756d2e61726974686d2e505047726f7570000000000200000000010000000002010000001c766572696669636174756d2e61726974686d2e4d6f645047726f7570000000000401000001010188cb0fcd7f00ffd629ee7c0426036c09cd1ae4576e3cde79680733bd13b0b1ef6ace0082d1cc0839d8d8f89d302570dcd4b7178fd8edfd54166d891b5f5b435c0cba214c471dda545897a12a9b53956fb76a6d647295011bec650e0609b50f97ffa16201ffd5b6368083965abf0a2f73ae0c2a9dc315ca63253df511176551961440aebbee1495c5bf318b9228c77938c4508063048161e9e4d83cbec3a3c16d856d1cf4d5f5c10d979476b39cd3541786fbc22d12326d8c66119a847c360e36294d4e1d14b1f80757f9fbfec49146e86b60130ecda55ac889aa733198a849946656c37cb5cbe3fd60d92900476ee6a9dac4825d89296fb5601a357de2121537010000010100c46587e6bf807feb14f73e021301b604e68d722bb71e6f3cb40399de89d858f7b567004168e6041cec6c7c4e9812b86e6a5b8bc7ec76feaa0b36c48dafada1ae065d10a6238eed2a2c4bd0954da9cab7dbb536b2394a808df632870304da87cbffd0b100ffeadb1b4041cb2d5f8517b9d706154ee18ae531929efa888bb2a8cb0a20575df70a4ae2df98c5c91463bc9c622840318240b0f4f26c1e5f61d1e0b6c2b68e7a6afae086cbca3b59ce69aa0bc37de116891936c63308cd423e1b071b14a6a70e8a58fc03abfcfdff6248a37435b0098766d2ad6444d53998cc5424ca332b61be5ae5f1feb06c948023b77354ed62412ec494b7dab00d1abef1090a9b010000010100e25212162cb0c7247fe38c94ee63c2f28af46f64aee6b967e6f77d3bee673db34346132755152d283644b7c9a7a97764862fa53466d1da6b24ccc105240829c8dfbf923e34bc01e49c1642cea67c183e13fccbe213eb2668cca873a44f2b43a76708b158ab785400750a132a754bf50eb290b84118b895837d1016e6bf957287cdb5bfbb360d2a9e4235be011f116be0bdd40423f60e22a65f3e323f5bb0eebc9e6f30fd3883ea9e9e8f7709df6aa6ad1cc3a834438e835c3f348c6a9f2b4c92dfc058f3bf375ec9bc5d9a4cf447f5a15e44632284d44b74901001e6b9fc30ea5e49ee15ac823205318a5af618d471fc7c8918d061043b58d2513bd3f13038be01000000040000000100000000020100000004000000000100000004000000000000000002010000010100e25212162cb0c7247fe38c94ee63c2f28af46f64aee6b967e6f77d3bee673db34346132755152d283644b7c9a7a97764862fa53466d1da6b24ccc105240829c8dfbf923e34bc01e49c1642cea67c183e13fccbe213eb2668cca873a44f2b43a76708b158ab785400750a132a754bf50eb290b84118b895837d1016e6bf957287cdb5bfbb360d2a9e4235be011f116be0bdd40423f60e22a65f3e323f5bb0eebc9e6f30fd3883ea9e9e8f7709df6aa6ad1cc3a834438e835c3f348c6a9f2b4c92dfc058f3bf375ec9bc5d9a4cf447f5a15e44632284d44b74901001e6b9fc30ea5e49ee15ac823205318a5af618d471fc7c8918d061043b58d2513bd3f13038be010000010100a5fa8159068f2fcba2b6e773091ed4c255b5510a217211905356ff96f3404279c4bd2dcdf5ccc0edf3ba6e32277d2807876d6118d49685d97e6fd535550919157146322e6d79cfa5df6800fe80cccf91d18ff336adbf41593cedc8eb3ae55f89b150433bfacc475e42fe2bd547c5fb1350304153ebea56d947afb81899a9ee78ab57602eb22f1391f5714f4f1d134056e9b0f6963c14f93bfc76523cf4021637ec423af2e6c8370533acf2cbafc31c00c71b1fe66ed5b8d623983b0ab49ac8193d9a4d59dda9438bca339a8245a9e12fd5ce669aa1494c2755efffb3a319a97fa0deb2ae35e2643e663843725ec0885e1783a8dfc5a2a3497e6cdf1cc538f638";
    protected static RandomSource randomSource;
    protected static int certainty;

    
	//private int prueba2;
	@Override
	public void init() {
		// TODO Auto-generated method stub
		/*try {
		textoCifrado = encryption(parameter1);
		}
		catch (Exception e) {
			System.out.println(e.getStackTrace());
			return null;
		}
		*/
		
		//prueba2 = 3;
		super.init();
	}
	
	public String encrypt(String plainText) {
		
        randomSource = new PRGHeuristic();
        certainty = 100;
        
        try {
        	PGroupElement fullPublicKey = MixNetElGamalInterface.stringToPublicKey(
        									interfaceName, publicKeyString, randomSource, certainty);
			return encryptVote(plainText, fullPublicKey);
			
		}
		catch (Exception e) {
			System.out.println(e.getStackTrace());
			return null;
		}

	}
	
    protected static void setup()
        throws Exception {
        if (pGroup == null) {
            rs = new PRGHeuristic(new String("Seed").getBytes());
            pGroup = new ModPGroup(2048);
            crhf = new HashfunctionHeuristic("SHA-256");
        }
    }
    public static boolean encryptionCheck(String plaintext) throws Exception {
        setup();
        int statDist = 100;
        CryptoKeyGen keyGen = new CryptoKeyGenCramerShoup(pGroup, crhf);
        CryptoKeyPair keyPair = keyGen.gen(rs, statDist);
        
        byte[] plaintextBytes = plaintext.getBytes();
        String label = "red label";
        byte[] labelBytes = label.getBytes();
        byte[] ciphertext = keyPair.getPKey().encrypt(labelBytes, plaintextBytes, rs, statDist);
        byte[] decryptedPlaintextBytes = keyPair.getSKey().decrypt(labelBytes, ciphertext);
        if (!Arrays.equals(decryptedPlaintextBytes, plaintextBytes)) {
            return false;
        }
        System.out.println("Cifrado!");
        return true;
    }
    
    public static String encryption(String plaintext) throws Exception {
        setup();
        int statDist = 100;
        CryptoKeyGen keyGen = new CryptoKeyGenCramerShoup(pGroup, crhf);
        CryptoKeyPair keyPair = keyGen.gen(rs, statDist);
        
        byte[] plaintextBytes = plaintext.getBytes();
        String label = "red label";
        byte[] labelBytes = label.getBytes();
        byte[] ciphertext = keyPair.getPKey().encrypt(labelBytes, plaintextBytes, rs, statDist);
        System.out.println("Cifrado!");
        return ciphertext.toString();
    }
    
 
    protected static String encryptVote(String plaintext,
        PGroupElement fullPublicKey) throws Exception {
 
        // Recover key from input
        PGroupElement basicPublicKey =
            ((PPGroupElement)fullPublicKey).project(0);
        PGroupElement publicKey =
            ((PPGroupElement)fullPublicKey).project(1);
 
        PGroup basicPublicKeyPGroup = basicPublicKey.getPGroup();
        PGroup publicKeyPGroup = publicKey.getPGroup();
 
        // Get interface
        MixNetElGamalInterface mixnetInterface =
            MixNetElGamalInterface.getInterface(interfaceName);
 
        // Generate plaintext
        PGroupElement[] m_a = new PGroupElement[1];
        byte[] iBytes = plaintext.getBytes();
        m_a[0] = publicKeyPGroup.encode(iBytes, 0, iBytes.length);
 
        // Encode plaintexts as group elements.
        PGroupElementArray m = publicKeyPGroup.toElementArray(m_a);
 
        // Encrypt the result.
        PRG prg = new PRGHeuristic();
        long now = System.currentTimeMillis();
        String nowString = String.valueOf(now) + String.valueOf(now);
        byte[] prgSeed = nowString.getBytes();
        // byte[] prgSeed = new byte[prg.minNoSeedBytes()];
        // Arrays.fill(prgSeed, (byte)0);
        // prg.setSeed(prgSeed);
        prg.setSeed(prgSeed);
        PRing randomizerPRing = basicPublicKeyPGroup.getPRing();
 
        PRingElementArray r =
            randomizerPRing.randomElementArray(1, prg, 20);
 
        PGroupElementArray u = basicPublicKey.exp(r);
        PGroupElementArray v = publicKey.exp(r).mul(m);
 
        PGroupElementArray ciphs =
            ((PPGroup)fullPublicKey.getPGroup()).product(u, v);
 
        PGroupElement[] ciphElements = ciphs.elements();
 
        // return ciphertext using the format of the interface.
        return mixnetInterface.ciphertextToString(ciphElements[0]);
    }
 
    
    
    //Metodo de prueba para devolver valores a js
    public String devuelve(String texto) {
    	textoCifrado = texto;
    	return texto;
    }
    
	/*   public void paint(java.awt.Graphics g)
	   {
	        //g.drawString("Applet de Verificatum .... Versión 0.0.1",50,25);
	        //g.drawString("Parameter 1 is: " + parameter1,50,25);
	        g.drawString("Texto encriptado: " + textoCifrado,50,50);
	        g.drawLine(0, 0, 400, 0);
	        g.drawLine(0, 100, 400, 100);
	        g.drawLine(0, 0, 0, 100);
	        g.drawLine(400, 0, 400, 100);
	        
	        System.out.println("LOG: Applet de Verificatum .... Versión 0.0.1");
	    }
	*/ 
}
