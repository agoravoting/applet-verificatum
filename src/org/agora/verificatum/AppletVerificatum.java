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

public class AppletVerificatum extends Applet {

    /**
    *
    */
    private static final long serialVersionUID = -1423669527827145571L;
	  private String textoCifrado;
    protected static PGroup pGroup;
    protected static RandomSource rs;
    protected static Hashfunction crhf;

    protected static String interfaceName = "native";
    protected static RandomSource randomSource;
    protected static int certainty;
    private String publicKeyString;
    
	@Override
	public void init() {		
		this.publicKeyString = this.getParameter("combined_public_key");
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
    
}
