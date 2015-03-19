/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gpake;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Taras Mychaskiw
 */
public class PPK implements PAKE {

    private final static String hmacName = "HMac-SHA256";

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger r;//p = r * q + 1;
    private final BigInteger g;
    private final BigInteger s; //password

    private PPK[] group;
    private int pos;

    private BigInteger x;
    private BigInteger[] m;

    private BigInteger y;
    private BigInteger gPowY;
    private BigInteger gPowZ;
    private SchnorrZKP schnorrY;

    private BigInteger gPowZPowY;
    private BigInteger[] pairwiseKeysMAC;
    private BigInteger[] pairwiseKeysKC;
    private BigInteger[] hMacsMAC;
    private BigInteger[] hMacsKC;
    private ChaumPedersonZKP chaum;

    private String signerID;

    private final BigInteger h1Const;
    private final BigInteger h3Const;

    public PPK(BigInteger p, BigInteger q, BigInteger g, BigInteger h1Const, BigInteger h3Const, String password) {
        this.p = p;
        this.q = q;
        this.r = p.subtract(BigInteger.ONE).divide(q);
        this.g = g;
        this.s = SHA256.get(password);
        this.h1Const = h1Const;
        this.h3Const = h3Const;
    }

    /**
     * Returns the number of rounds this PAKE has
     *
     * @return the number of rounds of communication
     */
    @Override
    public int getNumRounds() {
        return 2;
    }

    /**
     * Performs round one. P_i sends {g_s^{x_i}, g^{y_i}, zkp{y_i}}
     */
    private void roundOne() {

        x = BigIntegers.createRandomInRange(BigInteger.ZERO, q.subtract(BigInteger.ONE), new SecureRandom());
        BigInteger gPowX = g.modPow(x, p);
        m = new BigInteger[group.length];
        
        for (int i = 0; i < group.length; i++) {
            if (group[i] == this) {
                continue;
            }
            // Need to broadcast a different g^x*h1(x_i, x_j, s)^r to each group member.
            m[i] = gPowX.multiply(h1(pos, i, s).modPow(r, p));
        }
        
        y = BigIntegers.createRandomInRange(BigInteger.ZERO, q.subtract(BigInteger.ONE), new SecureRandom());
        gPowY = g.modPow(y, p);
        schnorrY = new SchnorrZKP(p, q, g, gPowY, y, signerID);
    }

    /**
     * Performs round two.
     */
    private void roundTwo() {

        pairwiseKeysMAC = new BigInteger[group.length];
        pairwiseKeysKC = new BigInteger[group.length];
        hMacsMAC = new BigInteger[group.length];
        hMacsKC = new BigInteger[group.length];

        gPowZPowY = gPowZ.modPow(y, p);
        chaum = new ChaumPedersonZKP(p, q, g, gPowY, y, gPowZ, gPowZPowY, signerID);
        for (int i = 0; i < group.length; i++) {
            if (group[i] == this) {
                continue;
            }

            // rawKey is g^(x_i*x_j).
            BigInteger rawKey = group[i].m[pos].multiply(h1(i, pos, s).modPow(r, p).modInverse(p)).modPow(x, p);
            // Use a combination of both keys to establish the pairwise key.
            
            int low = Math.min(i, pos);
            int high = Math.max(i, pos);
            
            rawKey = h3(low, high, group[low].m[high], group[high].m[low], rawKey, s).mod(p);
            pairwiseKeysMAC[i] = SHA256.get(rawKey, "MAC");
            pairwiseKeysKC[i] = SHA256.get(rawKey, "KC");

            hMacsMAC[i] = getMAC(new SecretKeySpec(pairwiseKeysMAC[i].toByteArray(), hmacName), this);
            hMacsKC[i] = getKC(new SecretKeySpec(pairwiseKeysKC[i].toByteArray(), hmacName), this, group[i]);
        }
    }

    /**
     * Performs a round of communication.
     *
     * @param round which round to do
     * @throws UnsupportedOperationException if round > getNumRounds() || round
     * < 1
     */
    @Override
    public void doRound(int round) {
        if (round > getNumRounds() || round < 1) {
            throw new UnsupportedOperationException();
        } else if (round == 1) {
            roundOne();
        } else {
            roundTwo();
        }
    }

    /**
     * Verifies the Z value.
     *
     * @param left the PAKE previous to this one
     * @param right the PAKE after this one
     * @return true if Z is verified
     * @throws SecurityException on failure, describing the error
     */
    @Override
    public boolean verifyZ(PAKE left, PAKE right) {
        PPK sLeft = (PPK) left;
        PPK sRight = (PPK) right;
        gPowZ = sLeft.gPowY.modInverse(p).multiply(sRight.gPowY).mod(p);
        if (gPowZ.equals(BigInteger.ONE)) {
            throw new SecurityException("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for " + this);
        }
        return true;
    }

    /**
     * Verifies round one.
     *
     * @return true if round one was successful
     */
    private boolean verifyOne() {
        for (PPK member : group) {
            if (member == this) {
                continue;
            }
            if (member.m[pos].equals(BigInteger.ZERO)) {
                throw new SecurityException("Round 1 verification failed at checking g^{ji} !=1");
            }
            if (!SchnorrZKP.verify(p, q, g, member.gPowY, member.schnorrY, member.signerID)) {
                throw new SecurityException("Round 1 verification failed at checking SchnorrZKP for yi. (i,j)=" + "(" + this + "," + member + ")");
            }
        }
        return true;
    }

    /**
     * Verifies round two.
     *
     * @return true if round two was successful
     */
    private boolean verifyTwo() {
        for (int i = 0; i < group.length; i++) {
            if (group[i] == this) {
                continue;
            }

            if (!ChaumPedersonZKP.verify(p, q, g, gPowY, gPowZ, gPowZPowY, chaum, signerID)) {
                throw new SecurityException("Round 2 verification failed at checking jth Chaum-Pederson for (i,j)=(" + this + "," + group[i] + ")");
            }

            BigInteger KC = getKC(new SecretKeySpec(pairwiseKeysKC[i].toByteArray(), hmacName), group[i], this);
            if (!KC.equals(group[i].hMacsKC[pos])) {
                throw new SecurityException("Round 2 verification failed at checking KC for (i,j)=(" + this + "," + group[i] + ")");
            }

            BigInteger MAC = getMAC(new SecretKeySpec(pairwiseKeysMAC[i].toByteArray(), hmacName), group[i]);
            if (!MAC.equals(group[i].hMacsMAC[pos])) {
                throw new SecurityException("Round 2 verification failed at checking MAC for (i,j)=(" + this + "," + group[i] + ")");
            }
        }
        return true;
    }

    /**
     * Verifies a round of communication.
     *
     * @param round which round to do
     * @return true if the protocol is verified for the round specified
     * @throws UnsupportedOperationException if round > getNumRounds() || round
     * < 1
     * @throws SecurityException on failure, describing the error
     */
    @Override
    public boolean verifyRound(int round) {
        if (round > getNumRounds() || round < 1) {
            throw new UnsupportedOperationException();
        } else if (round == 1) {
            return verifyOne();
        } else {
            return verifyTwo();
        }
    }

    /**
     * @param key
     * @param ppk
     * @return HMAC for message authentication
     */
    private static BigInteger getMAC(SecretKey key, PPK ppk) {
        try {
            Mac mac = Mac.getInstance(hmacName, "BC");
            mac.init(key);
            mac.update(ppk.gPowY.toByteArray());
            mac.update(ppk.schnorrY.getGenPowV().toByteArray());
            mac.update(ppk.schnorrY.getR().toByteArray());
            mac.update(ppk.gPowZPowY.toByteArray());
            mac.update(ppk.chaum.getGPowS().toByteArray());
            mac.update(ppk.chaum.getGPowZPowS().toByteArray());
            mac.update(ppk.chaum.getT().toByteArray());
            return new BigInteger(mac.doFinal());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            throw new RuntimeException("getMAC threw " + ex);
        }
    }

    /**
     * @param key
     * @param first
     * @param second
     * @return the KC mac
     */
    private static BigInteger getKC(SecretKey key, PPK first, PPK second) {
        try {
            Mac mac = Mac.getInstance(hmacName, "BC");
            mac.init(key);
            mac.update("KC".getBytes());
            mac.update(new BigInteger(String.valueOf(first.pos)).toByteArray());
            mac.update(new BigInteger(String.valueOf(second.pos)).toByteArray());
            mac.update(first.m[second.pos].toByteArray());
            mac.update(second.m[first.pos].toByteArray());
            return new BigInteger(mac.doFinal());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            throw new RuntimeException("getKC threw " + ex);
        }
    }

    private BigInteger h1(int a, int b, BigInteger pass) {

        return SHA256.get(a, b, pass.add(this.h1Const)).mod(p);
    }

    private BigInteger h3(int a, int b, BigInteger gPowX, BigInteger gPowY, BigInteger gPowXY, BigInteger pass) {
        return SHA256.get(a, b, gPowX, gPowY, gPowXY, pass.add(this.h3Const)).mod(p);
    }

    /**
     * Returns the communication key, or null if all the rounds have not been
     * done yet.
     *
     * @return the key
     */
    @Override
    public BigInteger getKey() {
        int n = group.length;
        BigInteger first = group[getIDX(pos - 1, n)].gPowY.modPow(y.multiply(BigInteger.valueOf(n)), p);
        BigInteger last = first;
        for (int i = 0; i < (n - 1); i++) {
            BigInteger inter = group[getIDX(pos + i, n)].gPowZPowY.modPow(BigInteger.valueOf(n - 1 - i), p);
            last = last.multiply(inter).mod(p);
        }
        return SHA256.get(last);
    }

    private int getIDX(int i, int size) {
        i = i % size;
        if (i < 0) {
            return i + size;
        }
        return i;
    }

    /**
     * lets the PAKE know all the other members of the group
     *
     * @param group the group
     * @param pos the index of us in the group
     */
    @Override
    public void setGroup(PAKE[] group, int pos) {
        this.group = (PPK[]) group;
        this.pos = pos;
        signerID = String.valueOf(pos);
    }

    /**
     * @return string representation of this
     */
    @Override
    public String toString() {
        return "ppk #" + pos;
    }

}
