package org.agora;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.applet.Applet;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;
import java.security.cert.Certificate;

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

public class VotingApplet extends Applet {
    protected static final String interfaceName = "native";
    protected static final String publicKeyURLStr = "http://localhost:8080/publickey/voting/id/";
    protected static final String sendBallotsURLStr = "http://localhost:8080/send/ballots";
    protected static final int certainty = 100;
    protected static final String confLinux=
        "name=OpenSC-OpenDNIe\nlibrary=/usr/lib/opensc-pkcs11.so\n";
    protected static final String confWindows=
        "name=OpenSC-OpenDNIe\r\nlibrary=C:\\WINDOWS\\system32\\opensc-pkcs11.dll\r\n";
    protected static final String confMac=
        "name=OpenSC-OpenDNIe\nlibrary=/usr/local/lib/opensc-pkcs11.so\n";
    protected static final String certAlias="CertFirmaDigital";

    protected RandomSource mRandomSource = null;

    protected KeyStore mKeyStore = null;
    protected Certificate mCertificate = null;
    protected PrivateKey mPrivateKey = null;
    protected String mPin = null;

    /**
     * Initialize the applet.
     */
    protected void initialize() throws Exception {
        mRandomSource = new PRGHeuristic();

        // Create PKCS#11 provider
        String config = "";
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.startsWith("win")) {
            config = confWindows;
        } else if (osName.startsWith("lin")) {
            config = confLinux;
        } else if (osName.startsWith("mac")) {
            config = confMac;
        }

        Provider provider = new sun.security.pkcs11.SunPKCS11(
            new ByteArrayInputStream(config.getBytes()));
        Security.addProvider(provider);

        // Create the keyStore and initialize it with the PIN
        mKeyStore = KeyStore.getInstance("PKCS11", provider);

        // TODO: Show dialog asking for the PIN
        mPin = "1234";
        mKeyStore.load(null, mPin.toCharArray());

        // Find signing cert in the cert list
        Certificate mCertificate = null;
        for (Enumeration<String> e = mKeyStore.aliases(); e.hasMoreElements();) {
            String alias =e.nextElement();
            if (alias.equals(certAlias)) {
                mCertificate = mKeyStore.getCertificate(alias);
            }
        }
        if (mCertificate == null) {
            throw new Exception("Signature certificate not found");
        }

        Key key = mKeyStore.getKey(certAlias, mPin.toCharArray());
        if(!(key instanceof PrivateKey)) {
            throw new Exception("The certificate has no associated private key");
        }
        mPrivateKey = (PrivateKey)key;
    }

    /**
     * Processes and cast a vote.
     *
     * @param ballot ballot string. The format should be:
     *              "<vote 1 id>,<propossal 1 id>,[<vote n id>,<propossal n id>, ...]"
     * 
     * @return a list of comma-separated hashes of the votes if the votes were
     *         correctly casted, or "FAIL" otherwise.
     */
    public String vote(String ballot) {
        try {
            // 1. initialize the applet
            initialize();

            // 2. Obtain the ballots
            Vote[] votes = parseBallotString(ballot);

            // 3. Send the ballots to the agora server
            sendBallots(votes);

            String hashes = "";
            for (int i = 0; i < votes.length; i++) {
                hashes = hashes + votes[i].getHash() + ",";
            }
            // remove last ',' char at the end
            hashes = hashes.substring(0, hashes.length() - 1);

            return hashes;
        } catch (Exception e) {
            return "FAIL";
        }
    }

    /**
     * Sends the ballots to the agora server
     */
    protected void sendBallots(Vote []votes) throws Exception {
        // Needs to send three things:
        // 1. The DNIe certificate, serialized
        // 2. For each vote, the encrypted vote
        // 3. For each vote, the signature of the encrypted vote

        // TODO: serialize ballots
        String ballots = "TODO";
        URL sendBallotsURL = new URL(sendBallotsURLStr);
        // TODO: do output
        HttpURLConnection con = (HttpURLConnection)sendBallotsURL.openConnection();
        InputStream in = (InputStream) con.getContent();
        String status = in.toString();

        if (status == "SUCCESS") {
            return;
        } else {
            throw new Exception("There was a problem casting the ballot");
        }
    }

    /**
     * Converts the ballot string into an array of Vote class instances
     */
    private Vote[] parseBallotString(String ballot) throws Exception {
        String[] items = ballot.split(",");
        Vote[] votes = new Vote[items.length/2];
        for(int i = 0; i < items.length/2; i = i++) {
            int vote = Integer.parseInt(items[i*2]);
            int propossal = Integer.parseInt(items[i*2 + 1]);
            votes[i] = new Vote(vote, propossal);
        }
        return votes;
    }

    /**
     * Test method to be able to execute java -jar agora-applet.jar for testing
     * purposes
     */
    public static void main(String[] args2) throws Exception {
        VotingApplet applet = new VotingApplet();
        String ballotStr = "00,000043334,00,000043335";
        String hashes = applet.vote(ballotStr);
        System.out.println("vote result = " + hashes);
        System.exit(hashes != "FAIL" ? 0 : 1);
        return;
    }

    /**
     * Contains a vote clear text information in the vote and propossal properties.
     */
    public class Vote {
        protected int mVote = -1;
        protected int mPropossal = -1;
        protected PGroupElement mFullPublicKey = null;
        protected String mEncryptedVote = null;
        protected String mVoteSignature = null;
        protected String mHash = null;

        public Vote(int vote, int propossal) throws Exception {
            mVote = vote;
            mPropossal = propossal;

            obtainPublicKey();
            encrypt();
            sign();
        }

        // Obtain the public key for this propossal/voting
        protected void obtainPublicKey() throws Exception {
            URL publicKeyURL = new URL(publicKeyURLStr + "" + mPropossal);
            HttpURLConnection con = (HttpURLConnection)publicKeyURL.openConnection();
            InputStream in = (InputStream) con.getContent();
            String publicKeyString = in.toString();
            mFullPublicKey = MixNetElGamalInterface.stringToPublicKey(
                interfaceName, publicKeyString, mRandomSource, certainty);
        }

        protected void encrypt() throws Exception {
            String plaintext = "" + mVote;
            // Recover key from input
            PGroupElement basicPublicKey =
                ((PPGroupElement)mFullPublicKey).project(0);
            PGroupElement publicKey =
                ((PPGroupElement)mFullPublicKey).project(1);

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

            // TODO: Is this secure enough?
            long now = System.currentTimeMillis();
            String nowString = String.valueOf(now) + String.valueOf(now);
            byte[] prgSeed = nowString.getBytes();
            prg.setSeed(prgSeed);
            PRing randomizerPRing = basicPublicKeyPGroup.getPRing();

            PRingElementArray r =
                randomizerPRing.randomElementArray(1, prg, 20);

            PGroupElementArray u = basicPublicKey.exp(r);
            PGroupElementArray v = publicKey.exp(r).mul(m);

            PGroupElementArray ciphs =
                ((PPGroup)mFullPublicKey.getPGroup()).product(u, v);

            PGroupElement[] ciphElements = ciphs.elements();

            // set ciphertext using the format of the interface.
            mEncryptedVote = mixnetInterface.ciphertextToString(ciphElements[0]);

            // TODO
            mHash = "deadbeefdeadbeef";
        }

        /**
         * Signs the vote with the user's dnie
         */
        protected void sign() throws Exception {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(mPrivateKey);
            sig.update(mEncryptedVote.getBytes());

            /* firmamos los datos y retornamos el resultado */
            mVoteSignature = "" + sig.sign();
        }

        public int getVote() {
            return mVote;
        }

        public int getPropossal() {
            return mPropossal;
        }

        public String getEncryptedVote() {
            return mEncryptedVote;
        }

        public String getVoteSignature() {
            return mVoteSignature;
        }

        public String getHash() {
            // TODO
            return mHash;
        }

        public String toString() {
            return "vote id = " + mVote + ", propossal id = " + mPropossal;
        }
    }
}
