/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package gpake;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 * @author Taras Mychaskiw
 */
public class SchnorrZKP {

    private BigInteger genPowV = null;
    private BigInteger r = null;

    public SchnorrZKP(){}

    public SchnorrZKP(BigInteger p, BigInteger q, BigInteger gen, BigInteger genPowX, BigInteger x, String signerID){
        generateZKP(p, q, gen, genPowX, x, signerID);
    }

    public void generateZKP(BigInteger p, BigInteger q, BigInteger gen, BigInteger genPowX, BigInteger x, String signerID){
        /* Generate a random v from [1, q-1], and compute V = gen^v */
        BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, q.subtract(BigInteger.ONE), new SecureRandom());
        genPowV = gen.modPow(v, p);
        BigInteger h = SHA256.get(gen,genPowV,genPowX,signerID); // h

        r = v.subtract(x.multiply(h)).mod(q); // r = v-x*h
    }

    public BigInteger getGenPowV() {
        return genPowV;
    }

    public BigInteger getR() {
        return r;
    }

    /*
     * Check
     * a) g^x in [1, q-1]
     * b) (g^x)^q = 1
     * c) g^v = g^r (g^x)^h
     *
     * Note: the case of x = 0 is not excluded in this routine. Handle that in the upstream if you need to.
     */
    public static boolean verify(BigInteger p, BigInteger q, BigInteger gen, BigInteger genPowX, BigInteger genPowV, BigInteger r, String userID) {

    	// ZKP: {V=gen^v, r}
    	BigInteger h = SHA256.get(gen, genPowV, genPowX, userID);

        return genPowX.compareTo(BigInteger.ZERO) == 1 && // gen^x > 0
            genPowX.compareTo(p) == -1 && // gen^x < p
            genPowX.modPow(q, p).compareTo(BigInteger.ONE) == 0 && // gen^x^q = 1
            /* A straightforward way to compute g^r * g^x^h needs 2 exp. Using
            * a simultaneous computation technique would only need 1 exp.
            */
            gen.modPow(r,p).multiply(genPowX.modPow(h,p)).mod(p).compareTo(genPowV) == 0; // gen^v=gen^r * gen^x^h
    }

    public static boolean verify(BigInteger p, BigInteger q, BigInteger gen, BigInteger genPowX, SchnorrZKP zkp, String userID){
        return verify(p, q, gen, genPowX, zkp.getGenPowV(), zkp.getR(), userID);
    }
}
