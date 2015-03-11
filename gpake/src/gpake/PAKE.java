/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gpake;

import java.math.BigInteger;

/**
 *
 * @author Taras
 */
public interface PAKE {

    /**
     * Returns the number of rounds this PAKE has
     * @return the number of rounds of communication
     */
    public int getNumRounds();

    /**
     * Performs a round of communication.
     * @param round which round to do
     * @throws UnsupportedOperationException if round > getNumRounds() || round < 1
     */
    public void doRound(int round);

    /**
     * Verifies a round of communication.
     * @param round which round to do
     * @return true if the protocol is verified for the round specified
     * @throws UnsupportedOperationException if round > getNumRounds() || round < 1
     * @throws RuntimeException on failure, describing the error
     */
    public boolean verifyRound(int round);

    /**
     * Returns the communication key, or null if all the rounds have not
     * been done yet.
     * @return the key
     */
    public BigInteger getKey();

    /**
     * Verifies the Z value.
     * @param left the PAKE previous to this one
     * @param right the PAKE after this one
     * @return true if Z is verified
     * @throws RuntimeException on failure, describing the error
     */
    public boolean verifyZ(PAKE left, PAKE right);

    /**
     * lets the PAKE know all the other members of the group
     * @param group the group
     * @param pos the index of us in the group
     */
    public void setGroup(PAKE[] group, int pos);
}
