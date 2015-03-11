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
public class ChaumPedersonZKP {

    private BigInteger gPowS = null;
    private BigInteger gPowZPowS = null;
    private BigInteger t = null;

    public ChaumPedersonZKP(){}

    public ChaumPedersonZKP(BigInteger p, BigInteger q, BigInteger g, BigInteger gPowX, BigInteger x,
                    BigInteger gPowZ, BigInteger gPowZPowX, String signerID){
        generateZKP(p, q, g, gPowX, x, gPowZ, gPowZPowX, signerID);
    }

    public void generateZKP(BigInteger p, BigInteger q, BigInteger g, BigInteger gPowX, BigInteger x,
                    BigInteger gPowZ, BigInteger gPowZPowX, String signerID) {

        // Generate s from [1, q-1] and compute (A, B) = (gen^s, genPowZ^s)
        BigInteger s = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
                        q.subtract(BigInteger.ONE), new SecureRandom());
        gPowS = g.modPow(s, p);
        gPowZPowS = gPowZ.modPow(s, p);

        BigInteger h = SHA256.get(g,gPowX,gPowZ,gPowZPowX,gPowS,gPowZPowS,signerID); // challenge

        t = s.subtract(x.multiply(h)).mod(q); // t = s-cr
    }

    public BigInteger getGPowS() {
        return gPowS;
    }

    public BigInteger getGPowZPowS() {
        return gPowZPowS;
    }

    public BigInteger getT() {
        return t;
    }

    /*
     * Full checks:
     * a) g^x in [1, q-1] and (g^x)^q = 1
     * b) g^z in [2, q-1] and (g^z)^q = 1
     * c) (g^z)^x in [1, q-1] and (g^z)^x = 1
     * d) g^s = g^t (g^x)^h
     * e) (g^z)^s = (g^z)^t ((g^z)^x)^h
     *
     * Notes:
     *
     * 1) The case of x = 0 is not excluded in this routine. Handle that in the upstream if you need to.
     * 2) Only partial checks are implemented in this routine, since some overlap with the previous
     *    checks in verifying the SchnorrZKP.
     *
     */
    public static boolean verify(BigInteger p, BigInteger q, BigInteger g, BigInteger gPowX, BigInteger gPowZ,
    		BigInteger gPowZPowX, BigInteger gPowS, BigInteger gPowZPowS, BigInteger t, String signerID) {

    	// ZKP: {A=g^s, B=(g^z)^s, t}
    	BigInteger h = SHA256.get(g,gPowX,gPowZ,gPowZPowX,gPowS,gPowZPowS,signerID);

    	// check a) - omitted as it's been done in round 1
    	/*
       	if (gPowX.compareTo(BigInteger.ONE) == -1 ||
       			gPowX.compareTo(q.subtract(BigInteger.ONE)) == 1 ||
       			gPowX.modPow(q, p).compareTo(BigInteger.ONE) != 0) {
       		return false;
       	}
       	*/

    	// Check b) - only partial; redundant checks not repeated. e.g., the order of g^z implied by ZKP checks in round 1
    	if (gPowZ.compareTo(BigInteger.ONE) == 0){
            return false;
    	}

    	// Check c) - full check
    	if (gPowZPowX.compareTo(BigInteger.ONE) == -1 ||
                gPowZPowX.compareTo(p.subtract(BigInteger.ONE)) == 1 ||
                gPowZPowX.modPow(q, p).compareTo(BigInteger.ONE) != 0) {

            return false;
       	}

    	// Check d) - Use the straightforward way with 2 exp. Using a simultaneous computation technique only needs 1 exp.
    	// g^s = g^t (g^x)^h
    	if (g.modPow(t, p).multiply(gPowX.modPow(h, p)).mod(p).compareTo(gPowS) != 0) {
            return false;
    	}
        // Check e) - Use the same method as in d)
        // (g^z)^s = (g^z)^t ((g^x)^z)^h
    	return gPowZ.modPow(t, p).multiply(gPowZPowX.modPow(h, p)).mod(p).compareTo(gPowZPowS) == 0;
    }

    public static boolean verify(BigInteger p, BigInteger q, BigInteger g, BigInteger gPowX, BigInteger gPowZ, BigInteger gPowZPowX, ChaumPedersonZKP zkp, String signerID) {
        return verify(p, q, g, gPowX, gPowZ, gPowZPowX, zkp.getGPowS(), zkp.getGPowZPowS(), zkp.getT(), signerID);
    }
}
