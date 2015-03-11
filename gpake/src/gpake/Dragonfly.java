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
public class Dragonfly implements PAKE {

    private final static BigInteger TWO = new BigInteger("2");
    private final static String hmacName = "HMac-SHA256";

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;
    private final BigInteger P;    //password map

    private Dragonfly[] group;
    private int pos;

    private BigInteger[] r, m, s, E;

    private BigInteger[] ss, hash;

    //private BigInteger[] pairwiseKeys;
    private BigInteger[] pairwiseKeysMAC;
    private BigInteger[] pairwiseKeysKC;
    private BigInteger[] hMacsMAC;
    private BigInteger[] hMacsKC;
    private ChaumPedersonZKP chaum;

    private BigInteger y, gPowY, gPowZ, gPowZPowY;
    private SchnorrZKP schnorr;
    private String signerID;

    public Dragonfly(BigInteger p, BigInteger q, BigInteger g, String password){
        this.p = p;
        this.q = q;
        this.g = g;
        this.P = g; //@todo security
    }

    /**
     * Returns the number of rounds this PAKE has
     * @return the number of rounds of communication
     */
    @Override
    public int getNumRounds() {
        return 3;
    }

    /**
     * r_A,m_A = a random in [1..q]
     * s_A = r_A + m_A mod q
     * E_A = P^{-m_A}
     *
     * gpake: y random in [1..q-1]
     */
    private void roundOne(){
        r = new BigInteger[group.length];
        m = new BigInteger[group.length];
        s = new BigInteger[group.length];
        E = new BigInteger[group.length];
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }
            r[i] = BigIntegers.createRandomInRange(BigInteger.ONE, q, new SecureRandom());
            m[i] = BigIntegers.createRandomInRange(BigInteger.ONE, q, new SecureRandom());
            s[i] = r[i].add(m[i]).mod(q);
            E[i] = P.modPow(m[i].negate(), p);
        }
        y = BigIntegers.createRandomInRange(BigInteger.ZERO, q.subtract(BigInteger.ONE), new SecureRandom());
        gPowY = g.modPow(y, p);
        schnorr = new SchnorrZKP(p, q, g, gPowY, y, signerID);
    }

    /**
     * ss = P^{r_A * r_B} mod p
     */
    private void roundTwo(){
        ss = new BigInteger[group.length];
        hash = new BigInteger[group.length];
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }
            ss[i] = P.modPow(r[i].multiply(group[i].r[pos]), p);
            hash[i] = SHA256.get(ss[i], E[i], s[i], group[i].E[pos], group[i].s[pos], signerID);
        }
    }

    /**
     * Performs round three.
     */
    private void roundThree(){
        pairwiseKeysMAC = new BigInteger[group.length];
        pairwiseKeysKC = new BigInteger[group.length];
        hMacsMAC = new BigInteger[group.length];
        hMacsKC = new BigInteger[group.length];
        gPowZPowY = gPowZ.modPow(y, p);
        chaum = new ChaumPedersonZKP(p, q, g, gPowY, y, gPowZ, gPowZPowY, signerID);
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }
            BigInteger rawKey = SHA256.get(ss[i], E[i], group[i].E[pos], s[i], group[i].s[pos], q);
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
        else if (round == 2){
            roundTwo();
        }
        else {
            roundThree();
        }
    }

    /**
     * dragonfly has nothing to verify, but gpake version should verify zkp
     * @return
     */
    private boolean verifyOne(){
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }

            if (group[i].s[pos].compareTo(TWO) < 0){
                throw new SecurityException("Round 1 verification failed at checking small subgroup attack for (" + group[i] + "," + this + ")");
            }

            if (group[i].s[pos].equals(s[i]) && group[i].E[pos].equals(E[i])){
                throw new SecurityException("Round 1 verification failed at checking reflection attack for (" + group[i] + "," + this + ")");
            }

            if (!SchnorrZKP.verify(p, q, g, group[i].gPowY, group[i].schnorr, group[i].signerID)){
                throw new SecurityException("Round 1 verification failed at checking jth SchnorrZKP for " + group[i]);
            }
        }
        return true;
    }

    /**
     * verifies round two, ensure they get the same dragonfly key
     * @return
     */
    private boolean verifyTwo(){
        //pairwiseKeys = new BigInteger[group.length];
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }

            BigInteger h = SHA256.get(ss[i], group[i].E[pos], group[i].s[pos], E[i], s[i], group[i].signerID);
            if (!h.equals(group[i].hash[pos])){
                throw new SecurityException("Round 2 verification failed at checking hash for (i,j)=("+this+","+group[i]+")\n"+h+"\n"+hash[i]);
            }
            //pairwiseKeys[i] = SHA256.get(ss[i], E[i], group[i].E[pos], s[i], group[i].s[pos], q);
        }
        return true;
    }

    /**
     * Verifies round three - gpake keys
     * @return true if round two was successful
     */
    private boolean verifyThree(){
        for (int i = 0; i < group.length; i++){
            if (group[i] == this){ continue; }

            if (!ChaumPedersonZKP.verify(p, q, g, group[i].gPowY, group[i].gPowZ, group[i].gPowZPowY, group[i].chaum, group[i].signerID)){
                throw new SecurityException("Round 3 verification failed at checking jth Chaum-Pederson for (i,j)=("+this+","+group[i]+")");
            }

            BigInteger KC = getKC(new SecretKeySpec(pairwiseKeysKC[i].toByteArray(), hmacName), group[i], this);
            if (!KC.equals(group[i].hMacsKC[pos])){
                throw new SecurityException("Round 3 verification failed at checking KC for (i,j)=("+this+","+group[i]+")");
            }

            BigInteger MAC = getMAC(new SecretKeySpec(pairwiseKeysMAC[i].toByteArray(), hmacName), group[i]);
            if (!MAC.equals(group[i].hMacsMAC[pos])){
                throw new SecurityException("Round 3 verification failed at checking MAC for (i,j)=("+this+","+group[i]+")");
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
        else if (round == 2){
            return verifyTwo();
        }
        else {
            return verifyThree();
        }
    }

    /**
     * @param key
     * @param dragon
     * @return HMAC for message authentication
     */
    private static BigInteger getMAC(SecretKey key, Dragonfly dragon) {
        try {
            Mac mac = Mac.getInstance(hmacName, "BC");
            mac.init(key);
            mac.update(dragon.gPowY.toByteArray());
            mac.update(dragon.schnorr.getGenPowV().toByteArray());
            mac.update(dragon.schnorr.getR().toByteArray());
            mac.update(dragon.gPowZPowY.toByteArray());
            mac.update(dragon.chaum.getGPowS().toByteArray());
            mac.update(dragon.chaum.getGPowZPowS().toByteArray());
            mac.update(dragon.chaum.getT().toByteArray());
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
    private static BigInteger getKC(SecretKey key, Dragonfly first, Dragonfly second) {
        try {
            Mac mac = Mac.getInstance(hmacName, "BC");
            mac.init(key);
            mac.update("KC".getBytes());
            mac.update(new BigInteger(String.valueOf(first.pos)).toByteArray());
            mac.update(new BigInteger(String.valueOf(second.pos)).toByteArray());
            //@todo security
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
     * Verifies the Z value.
     * @param left the PAKE previous to this one
     * @param right the PAKE after this one
     * @return true if Z is verified
     * @throws SecurityException on failure, describing the error
     */
    @Override
    public boolean verifyZ(PAKE left, PAKE right) {
        Dragonfly sLeft = (Dragonfly)left, sRight = (Dragonfly)right;
        gPowZ = sLeft.gPowY.modInverse(p).multiply(sRight.gPowY).mod(p);
        if (gPowZ.equals(BigInteger.ONE)){
            throw new SecurityException("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for " + this);
        }
        return true;
    }

    /**
     * lets the PAKE know all the other members of the group
     * @param group the group
     * @param pos the index of us in the group
     */
    @Override
    public void setGroup(PAKE[] group, int pos) {
        this.group = (Dragonfly[]) group;
        this.pos = pos;
        signerID = String.valueOf(pos);
    }

    /**
     * @return string representation of this
     */
    @Override
    public String toString(){
        return "dragon #" + pos;
    }
}
