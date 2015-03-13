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
 * @author Feng Hao, Xun Yi, Liqun Chen, Siamak F. Shahandashti; modifications by Taras Mychaskiw
 */
public class SPEKE implements PAKE {

    private final static BigInteger TWO = new BigInteger("2");
    private final static String hmacName = "HMac-SHA256";

    private SPEKE[] group;
    private int pos;

    private final BigInteger p; //big prime modulus
    private final BigInteger q; //(p-1)/2
    private final BigInteger g; //generator

    private final BigInteger gs;

    private BigInteger x;
    private BigInteger y;
    private BigInteger gsPowX;
    private BigInteger gPowY;
    private BigInteger gPowZ;
    private SchnorrZKP schnorr;

    private BigInteger gPowZPowY;
    private BigInteger[] pairwiseKeysMAC;
    private BigInteger[] pairwiseKeysKC;
    private BigInteger[] hMacsMAC;
    private BigInteger[] hMacsKC;
    private ChaumPedersonZKP chaum;

    private String signerID;

    public SPEKE(BigInteger p, BigInteger g, String password){
        this.p = p;
        q = p.subtract(BigInteger.ONE).divide(new BigInteger("2"));
        this.g = g;
        gs = SHA256.get(password);
    }

    /**
     * Returns the number of rounds this PAKE has
     * @return the number of rounds of communication
     */
    @Override
    public int getNumRounds() {
        return 2;
    }

    /**
     * Performs round one.
     * P_i sends {g_s^{x_i}, g^{y_i}, zkp{y_i}}
     */
    private void roundOne(){
        x = BigIntegers.createRandomInRange(BigInteger.ONE, q.subtract(BigInteger.ONE), new SecureRandom());
        y = BigIntegers.createRandomInRange(BigInteger.ZERO, q.subtract(BigInteger.ONE), new SecureRandom());
        gsPowX = gs.modPow(x, p);
        gPowY = g.modPow(y, p);
        schnorr = new SchnorrZKP(p, q, g, gPowY, y, signerID);
    }

    /**
     * Performs round two.
     */
    private void roundTwo(){
        pairwiseKeysMAC = new BigInteger[group.length];
        pairwiseKeysKC = new BigInteger[group.length];
        hMacsMAC = new BigInteger[group.length];
        hMacsKC = new BigInteger[group.length];
        gPowZPowY = gPowZ.modPow(y, p);
        chaum = new ChaumPedersonZKP(p, q, g, gPowY, y, gPowZ, gPowZPowY, signerID);
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }
            BigInteger rawKey = group[i].gsPowX.modPow(x, p);
            pairwiseKeysMAC[i] = SHA256.get(rawKey, "MAC");
            pairwiseKeysKC[i] = SHA256.get(rawKey, "KC");

            hMacsMAC[i] = getMAC(new SecretKeySpec(pairwiseKeysMAC[i].toByteArray(), hmacName), this);
            hMacsKC[i] = getKC(new SecretKeySpec(pairwiseKeysKC[i].toByteArray(), hmacName), this, group[i]);
        }
    }

    /**
     * Performs a round of communication.
     * @param round which round to do
     * @throws UnsupportedOperationException if round > getNumRounds() || round < 1
     */
    @Override
    public void doRound(int round) {
        if (round > getNumRounds() || round < 1){
            throw new UnsupportedOperationException();
        }
        else if (round == 1){
            roundOne();
        }
        else {
            roundTwo();
        }
    }

    /**
     * Verifies the Z value.
     * @param left the PAKE previous to this one
     * @param right the PAKE after this one
     * @return true if Z is verified
     * @throws SecurityException on failure, describing the error
     */
    @Override
    public boolean verifyZ(PAKE left, PAKE right){
        SPEKE sLeft = (SPEKE)left, sRight = (SPEKE)right;
        gPowZ = sLeft.gPowY.modInverse(p).multiply(sRight.gPowY).mod(p);
        if (gPowZ.equals(BigInteger.ONE)){
            throw new SecurityException("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for " + this);
        }
        return true;
    }

    /**
     * Verifies round one.
     * @return true if round one was successful
     */
    private boolean verifyOne(){
        for (SPEKE member : group) {
            if (member == this) {
                continue;
            }
            if (member.gsPowX.compareTo(TWO) < 0 || member.gsPowX.compareTo(p.subtract(TWO)) > 0) {
                throw new SecurityException("Round 1 verification failed at checking gs^{x_i} for " + member);
            }
            if (!SchnorrZKP.verify(p, q, g, member.gPowY, member.schnorr, member.signerID)) {
                throw new SecurityException("Round 1 verification failed at checking jth SchnorrZKP for for " + member);
            }
        }
        return true;
    }

    /**
     * Verifies round two.
     * @return true if round two was successful
     */
    private boolean verifyTwo(){
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }

            if (!ChaumPedersonZKP.verify(p, q, g, gPowY, gPowZ, gPowZPowY, chaum, signerID)){
                throw new SecurityException("Round 2 verification failed at checking jth Chaum-Pederson for (i,j)=("+this+","+group[i]+")");
            }

            BigInteger KC = getKC(new SecretKeySpec(pairwiseKeysKC[i].toByteArray(), hmacName), group[i], this);
            if (!KC.equals(group[i].hMacsKC[pos])){
                throw new SecurityException("Round 2 verification failed at checking KC for (i,j)=("+this+","+group[i]+")");
            }

            BigInteger MAC = getMAC(new SecretKeySpec(pairwiseKeysMAC[i].toByteArray(), hmacName), group[i]);
            if (!MAC.equals(group[i].hMacsMAC[pos])){
                throw new SecurityException("Round 2 verification failed at checking MAC for (i,j)=("+this+","+group[i]+")");
            }
        }
        return true;
    }

    /**
     * Verifies a round of communication.
     * @param round which round to do
     * @return true if the protocol is verified for the round specified
     * @throws UnsupportedOperationException if round > getNumRounds() || round < 1
     * @throws SecurityException on failure, describing the error
     */
    @Override
    public boolean verifyRound(int round) {
        if (round > getNumRounds() || round < 1){
            throw new UnsupportedOperationException();
        }
        else if (round == 1){
            return verifyOne();
        }
        else {
            return verifyTwo();
        }
    }

    /**
     * @param key
     * @param speke
     * @return HMAC for message authentication
     */
    private static BigInteger getMAC(SecretKey key, SPEKE speke) {
        try {
            Mac mac = Mac.getInstance(hmacName, "BC");
            mac.init(key);
            mac.reset();
            mac.update(speke.gPowY.toByteArray());
            mac.update(speke.schnorr.getGenPowV().toByteArray());
            mac.update(speke.schnorr.getR().toByteArray());
            mac.update(speke.gPowZPowY.toByteArray());
            mac.update(speke.chaum.getGPowS().toByteArray());
            mac.update(speke.chaum.getGPowZPowS().toByteArray());
            mac.update(speke.chaum.getT().toByteArray());
            return new BigInteger(mac.doFinal());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex){
            throw new RuntimeException("getMAC threw " + ex);
        }
    }

    /**
     * @param key
     * @param first
     * @param second
     * @return the KC mac
     */
    private static BigInteger getKC(SecretKey key, SPEKE first, SPEKE second) {
        try {
            Mac mac = Mac.getInstance(hmacName, "BC");
            mac.init(key);
            mac.update("KC".getBytes());
            mac.update(new BigInteger(String.valueOf(first.pos)).toByteArray());
            mac.update(new BigInteger(String.valueOf(second.pos)).toByteArray());
            mac.update(first.gsPowX.toByteArray());
            mac.update(second.gsPowX.toByteArray());
            return new BigInteger(mac.doFinal());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex){
            throw new RuntimeException("getKC threw " + ex);
        }
    }

    /**
     * Returns the communication key, or null if all the rounds have not
     * been done yet.
     * @return the key
     */
    @Override
    public BigInteger getKey() {
        int n = group.length;
        BigInteger first = group[getIDX(pos-1, n)].gPowY.modPow(y.multiply(BigInteger.valueOf(n)), p);
        BigInteger last = first;
        for (int i = 0; i < (n-1); i++){
            BigInteger inter = group[getIDX(pos+i, n)].gPowZPowY.modPow(BigInteger.valueOf(n-1-i), p);
            last = last.multiply(inter).mod(p);
        }
        return SHA256.get(last);
    }

    private int getIDX(int i, int size){
        i = i % size;
        if (i < 0){
            return i + size;
        }
        return i;
    }

    /**
     * lets the PAKE know all the other members of the group
     * @param group the group
     * @param pos the index of us in the group
     */
    @Override
    public void setGroup(PAKE[] group, int pos) {
        this.group = (SPEKE[]) group;
        this.pos = pos;
        signerID = String.valueOf(pos);
    }

    /**
     * @return string representation of this
     */
    @Override
    public String toString(){
        return "speke #" + pos;
    }
}
