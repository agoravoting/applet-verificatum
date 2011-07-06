package org.agora;

import java.util.Arrays;
import java.util.Random;
import java.applet.Applet;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.URLConnection;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.BoxLayout;
import javax.swing.BorderFactory;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import java.awt.Frame;
import java.awt.*;
import java.awt.event.*;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.MessageDigest;
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

/**
 * Class used in Agora to verify that a ballot is valid.
 */
public class BallotVerifier {
    protected static final String interfaceName = "native";

    protected RandomSource mRandomSource = null;

    protected Certificate mCertificate = null;
    protected PGroupElement[] mEncryptedVotes = null;

    protected String mSubjectCIF = null;
    protected String mSubjectName = null;
    protected String mSubjectSurname1 = null;
    protected String mSubjectSurname2 = null;
    /**
     * Verifies a ballot. Verifications:
     * 1. Checks that the vote is correctly encrpyted with the correct public keys
     * 2. Checks that the given dni-e certificate is valid and not revoked
     * 3. Check that the votes are signed with the given certificate
     * 4. Obtains user information from the certificate andreturns it
     *
     * @return "CIF (with number),Name,Surname1,Surname2" if all verifications
     *         passed or "FAIL" otherwise. For example, a possible output is:
     *         "00000000F,Pepito,De Los Palotes,Marianos"
     */
    public String verify(String serializedCertificate, String[] votes, String[] signatures, String[] propossalPublicKeys) {
        try {
            if (votes.length < 1 || votes.length != signatures.length ||
                votes.length != propossalPublicKeys.length) {
                throw new Exception("Invalid input data");
            }
            deserializeCertificate(serializedCertificate);
            checkVotesEncryption(votes);
            validateCertificate();
            checkSignatures(signatures);
            return mSubjectCIF + "," + mSubjectName + "," + mSubjectSurname1
                   + "," + mSubjectSurname2;
        } catch (Exception e) {
            return "FAIL";
        }
    }

    /**
     * Reads a Certificate instance from a string
     */
    protected void deserializeCertificate(String serializedCertificate)
        throws Exception
    {
        byte[] pickled = serializedCertificate.getBytes();
        InputStream in = new ByteArrayInputStream(pickled);
        ObjectInputStream ois = new ObjectInputStream(in);
        mCertificate = (Certificate)ois.readObject();
    }

    /**
     * Loads the vote string into PGroupElements. TODO: In the future, when we have
     * our own Mixnet Interface, this interface will verify if the vote is
     * valid using a random oracle proof embed in the ciphertext.
     */
    protected void checkVotesEncryption(String[] votes) throws Exception {
        mEncryptedVotes = new PGroupElement[votes.length];
        MixNetElGamalInterface mixnetInterface =
            MixNetElGamalInterface.getInterface(interfaceName);
        for (int i = 0; i < votes.length; i++) {
            // TODO
//             mEncryptedVotes[i] = mixnetInterface.stringToCiphertext(votes[i]);
        }
    }

    /**
     * Checks that the given certificate is valid.
     * 1. Check that it is valid (not expired etc).
     * 2. Check that the autority that signed is one of the three valid i.e.
     *    recognized authorities.
     * 3. Check via OCSP that the certificate is not revoked.
     */
    protected void validateCertificate() throws Exception {
        // TODO
    }

    protected void checkSignatures(String[] signatures) throws Exception {
        // TODO
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        for (int i = 0; i < signatures.length; i++) {
            String hash = new String(sha1.digest(mEncryptedVotes[i].toByteArray()));
            // decrypt signatures[i] into hash2
            String hash2 = "";
            if (hash != hash2) {
                throw new Exception("Invalid signature");
            }
        }
    }

    protected void init() throws Exception {
        mRandomSource = new PRGHeuristic();
    }

    /**
     * Call for testing. args = cert vote1 sig1 pk1 [voten sign pkn ...]
     */
    public static void main(String[] args) {
        BallotVerifier verifier = new BallotVerifier();

        // Check arguments
        if (args.length < 5 || args.length % 3 != 2) {
            System.out.println("Invalid arguments");
            System.exit(1);
            return;
        }

        // Parse arguments
        int numVotes = (args.length - 2) / 3;
        String serializedCertificate = args[1];
        String[] votes = new String[numVotes];
        String[] signatures = new String[numVotes];
        String[] propossalPublicKeys = new String[numVotes];

        for (int i = 0; i < numVotes; i++) {
            votes[i] = args[2 + i*3];
        }
        for (int i = 0; i < numVotes; i++) {
            signatures[i] = args[3 + i*3];
        }
        for (int i = 0; i < numVotes; i++) {
            propossalPublicKeys[i] = args[4 + i*3];
        }

        // Verify
        String result = verifier.verify(serializedCertificate, votes,
                                        signatures, propossalPublicKeys);
        System.out.println(result);
        System.exit(result != "FAIL" ? 0 : 1);
        return;
    }
}
