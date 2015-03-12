/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gpake;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Taras Mychaskiw
 */
public class SHA256 {

    public static BigInteger get(BigInteger g, BigInteger gPowX, BigInteger gPowZ, BigInteger gPowZPowX,
            BigInteger gPowS, BigInteger gPowXPowS, String userID) {

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            byte[] gBytes = g.toByteArray();
            byte[] gPowXBytes = gPowX.toByteArray();
            byte[] gPowZBytes = gPowZ.toByteArray();
            byte[] gPowZPowXBytes = gPowZPowX.toByteArray();
            byte[] gPowSBytes = gPowS.toByteArray();
            byte[] gPowXPowSBytes = gPowXPowS.toByteArray();
            byte[] userIDBytes = userID.getBytes();

            sha256.update(ByteBuffer.allocate(4).putInt(gBytes.length).array());
            sha256.update(gBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowXBytes.length).array());
            sha256.update(gPowXBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowZBytes.length).array());
            sha256.update(gPowZBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowZPowXBytes.length).array());
            sha256.update(gPowZPowXBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowSBytes.length).array());
            sha256.update(gPowSBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowXPowSBytes.length).array());
            sha256.update(gPowXPowSBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array());
            sha256.update(userIDBytes);
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static BigInteger get(BigInteger gen, BigInteger genPowV, BigInteger genPowX, String userID) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            byte[] genBytes = gen.toByteArray();
            byte[] genPowVBytes = genPowV.toByteArray();
            byte[] genPowXBytes = genPowX.toByteArray();
            byte[] userIDBytes = userID.getBytes();

            // Prepend each item with a 4-byte length
            sha256.update(ByteBuffer.allocate(4).putInt(genBytes.length).array());
            sha256.update(genBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(genPowVBytes.length).array());
            sha256.update(genPowVBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(genPowXBytes.length).array());
            sha256.update(genPowXBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array());
            sha256.update(userIDBytes);

            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static BigInteger get(String s) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(s.getBytes());
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException e) {
        }
        return null;
    }

    public static BigInteger get(BigInteger s) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(s.toByteArray());
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException e) {
        }
        return null;
    }

    public static BigInteger get(BigInteger s, String str) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(s.toByteArray());
            sha256.update(str.getBytes());
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static BigInteger get(BigInteger ss, BigInteger Ea, BigInteger sa, BigInteger Eb, BigInteger sb, String signerID) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(ss.toByteArray());
            sha256.update(Ea.toByteArray());
            sha256.update(sa.toByteArray());
            sha256.update(Eb.toByteArray());
            sha256.update(sb.toByteArray());
            sha256.update(signerID.getBytes());
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static BigInteger get(BigInteger ss, BigInteger Ea, BigInteger Eb, BigInteger sa, BigInteger sb, BigInteger q) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(ss.toByteArray());
            sha256.update(Ea.multiply(Eb).toByteArray());
            sha256.update(sa.add(sb).mod(q).toByteArray());
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static BigInteger get(int a, int b, BigInteger s) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(Integer.toString(a).getBytes());
            sha256.update(Integer.toString(b).getBytes());
            sha256.update(s.toByteArray());
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static BigInteger get(int a, int b, BigInteger gPowX, BigInteger gPowY, BigInteger gPowXY, BigInteger pass) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(Integer.toString(a).getBytes());
            sha256.update(Integer.toString(b).getBytes());
            sha256.update(gPowX.toByteArray());
            sha256.update(gPowY.toByteArray());
            sha256.update(gPowXY.toByteArray());
            sha256.update(pass.toByteArray());
            return new BigInteger(sha256.digest());
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }
}
