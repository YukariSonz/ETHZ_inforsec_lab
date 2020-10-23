package students.exercise2;

import students.IGroupElement;
import students.elgamal.ElgamalCiphertext;

/**
 * An interface for an adversary in the Ind-CPA security game of Elgamal's PKE
 * scheme.
 * <p>
 * An adversary who implements this interface will be state-based and can be
 * used to decide challenge ciphertexts in the Ind CPA game.
 * <p>
 * For this end, the methods init, getCandidateMessagePair and
 * solveIndCPAChallenge must be called in this order. If those methods are not
 * called in the correct order or if invalid group elements have been given to
 * the adversary, then its response in solveIndCPAChallenge will be erroneous.
 * 
 * @author Akin
 */
public interface IElgamalIndCPAAdversary {
    /**
     * Call this method to start an Ind-CPA game with this adversary. The adversary
     * will save a copy of the given generator and public key.
     * <p>
     * Calling this method a second time will cause this instance to overwrite it
     * last saved values.
     * <p>
     * If one of the both inputs is NOT a valid group element, then this method will
     * do nothing (the adversary will not save any values).
     * 
     * @param generator A generator of the generic group which encodes ONE. This
     *                  instance will save a copy of generator.
     * @param publicKey A public key of the Elgamal PKE scheme with respect to the
     *                  given generator.
     */
    public void init(IGroupElement generator, IGroupElement publicKey);

    /**
     * Call this method after you have called init. The adversary will generate two
     * plaintexts (of type IGroupElement) and give them back. If init has not been
     * called before, this method will return null.
     * <p>
     * Calling this method will cause this instance to save copies of both
     * messages. Calling this method a second time will cause this instance to
     * overwrite it last saved values.
     * 
     * @return returns a CandidateMessagePair which contains two IGroupElements. The
     *         first entry is message0 (the first message the adversary has chosen)
     *         and the second one is message1 (the second message the adversary has
     *         chosen).
     */
    public CandidateMessagePair<IGroupElement> getCandidateMessages();

    /**
     * Call this method after you have called init and getCandidateMessages and give
     * it a ciphertext of an instance of Elgamal's PKE scheme whose public key and
     * group generator you supplied in your init call.
     * 
     * @param ciphertext a possible ciphertext of Elgamal's PKE scheme. Look up the
     *                   method encrypt of the class ElgamalPKEScheme to see how
     *                   ciphertexts should be constructed.
     * @return If ciphertext is a valid encryption of message0, the first message
     *         returned by getCandidateMessages, then this method should return 0.
     *         If ciphertext is a valid encryption of message1, the second message
     *         returned by getCandidateMessages, then this method should return 1.
     *         If neither of the above cases does occur, then this method will
     *         return 0 or 1 (without any guarantees which value will be returned).
     *         If init or getChallengeMessages has never been called before, this
     *         method will return 0 or 1 (without any guarantees which value will be
     *         returned).
     */
    public int solveIndCPAChallenge(ElgamalCiphertext ciphertext);
}
