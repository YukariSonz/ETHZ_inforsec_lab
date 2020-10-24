package students.exercise1;

import students.IGroupElement;

/**
 * Instances of this interface implement a TIGHT reduction from solving a CDH
 * challenge to extracting a message from a ciphertext of Elgamal's PKE scheme.
 * I.e. classes who implement this interface have to implement a method which --
 * when given a CDH challenge and an OwCPA-adversary for Elgamal's PKE scheme --
 * returns a solution to the given CDH challenge.
 * 
 * @author Akin
 */
public interface ICDHOwCPAElgamalReduction {
    /**
     * This method shall compute a solution to the given CDH challenge by using the
     * given adversary for the Ow-CPA security game for Elgamal's PKE schemes.
     * <p>
     * Note, that this reduction has to be TIGHT. This means, this method shall make
     * at most one query to the adversary where it asks to extract a message from a
     * ciphertext.
     * 
     * @param cdhChallenge a CDH challenge tuple which consists of three group
     *                     elements (g, g^x, g^y). This method shall compute a
     *                     solution to this challenge tuple, i.e. it shall return
     *                     the group element g^(xy).
     * @param adversary    an adversary in the Ow-CPA security of Elgamal's PKE
     *                     scheme. I.e., this adversary can extract plaintexts from
     *                     ciphertexts of Elgamal's PKE scheme, when correctly
     *                     instantiated. Note, that this reduction has to be TIGHT.
     *                     I.e., this method may call the extractMessage(ciphertext)
     *                     method of adversary at most once.
     * @return this method shall return a group element which is a solution to the
     *         CDH challenge tuple (g, g^x, g^y). This means, this method must at
     *         the end return a group element g^(x*y).
     */
    IGroupElement solveCDH(CDHChallenge cdhChallenge, IElgamalOwCPAAdversary adversary);
}
