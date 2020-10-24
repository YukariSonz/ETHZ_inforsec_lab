package students.exercise3;

import students.IGroupElement;
import students.elgamal.ElgamalCiphertext;
import students.exercise2.CandidateMessagePair;

/**
 * An interface for an adversary in the multi-user Ind-CPA security game of
 * Elgamal's PKE scheme.
 * <p>
 * An adversary who implements this interface will be state-based and can be
 * used to decide arrays of challenge ciphertexts in the multi-user Ind CPA
 * game.
 * <p>
 * For this end, the methods init, getCandidateMessagePair and
 * solveIndCPAChallenge must be called in this order. If those methods are not
 * called in the correct order or if invalid group elements have been given to
 * the adversary, its response in solveIndCPAChallenge will be erroneous.
 * <p>
 * <b>IMPORTANT NOTE</b>: This adversary will only work correctly, if the public
 * keys you give in the init() method are exactly the second arguments of the
 * DDH challenges you queried the last time from the rerandomization oracle.
 * This means, if you call init(generator, publicKeys), then publicKeys must be
 * an array of the n elements g^(d_1), ..., g^(d_n) which come from the
 * rerandomized DDH challenges (g, g^(d_1), g^(e_1), g^(f_1)), ..., (g, g^(d_n),
 * g^(e_n), g^(f_n)) (<b>in exactly this order</b>) you received from your last
 * rerandomizationOracle.rerandomizeChallenge call, where n is the number of
 * users returned by getNumberUsers().
 * 
 * @author Akin
 */
public interface IElgamalMultiUserIndCPAAdversary {
    /**
     * Returns the number of users in the multi-user Ind-CPA security game of this
     * adversary. This number determines the number of public keys with which this
     * adversary must be initialized. Further, this number determines how many pairs
     * of challenge messages this adversary will choose and how many ciphertexts it
     * needs to solve an Ind-CPA challenge.
     * 
     * @return the number of users in the multi-user Ind-CPA security game of this
     *         adversary.
     */
    int getNumberUsers();

    /**
     * Call this method to start a multi-user Ind-CPA game with this adversary. The
     * adversary will save a copy of the given generator and public keys.
     * <p>
     * Calling this method a second time will cause this instance to overwrite it
     * last saved values.
     * <p>
     * If one of the inputs is NOT a valid group element, then this method will do
     * nothing (the adversary will not save any values).
     * <p>
     * <b>IMPORTANT NOTE</b>: This adversary will only work correctly if the public
     * keys you give in this method are exactly the second arguments of the DDH
     * challenges you queried the last time from the rerandomization oracle. This
     * means: when you call init(generator, publicKeys), then publicKeys must be an
     * array of the n elements g^(d_1), ..., g^(d_n) which come from the
     * rerandomized DDH challenges (g, g^(d_1), g^(e_1), g^(f_1)), ..., (g, g^(d_n),
     * g^(e_n), g^(f_n)) (<b>in exactly this order</b>) you received from your last
     * rerandomizationOracle.rerandomizeChallenge call, where n is the number of
     * users returned by getNumberUsers().
     * <p>
     * If publicKeys is not equal to the second arguments of the rerandomized DDH
     * challenges of your last rerandomizeChallenge call, then this method will do
     * nothing. I.e., it will not save the generator and the public keys, and it
     * will return null, when you call getCandidateMessages.
     * 
     * @param generator A generator of the group which encodes ONE. This instance
     *                  will save a copy of generator.
     * @param publicKey An array of public keys of Elgamal's PKE scheme with respect
     *                  to the given generator. The size of this array (i.e. the
     *                  number of public keys) should be equal to the number of
     *                  users, i.e., the number returned by getNumberUsers().
     */
    void init(IGroupElement generator, IGroupElement[] publicKeys);

    /**
     * Call this method after you have called init. The adversary will generate n
     * pairs of plaintexts (of type IGroupElement) and return them (where n is the
     * number of users in the multi-user Ind-CPA game of this adversary). If init
     * has not been called before, then this method will return null.
     * <p>
     * Calling this method will cause this instance to save copies of all messages.
     * Calling this method a second time will cause this instance to overwrite its
     * last saved values.
     * 
     * @return returns n CandidateMessagePairs which contains two IGroupElements.
     *         The first entry is message0 (the first message the adversary has
     *         chosen) and the second one is message1 (the second message the
     *         adversary has chosen). Each candidate message pair has a different
     *         pair of messages (message0, message1).
     */
    CandidateMessagePair<IGroupElement>[] getCandidateMessages();

    /**
     * Call this method after you have called init and getCandidateMessages and give
     * it an array of n ciphertexts of Elgamal's PKE scheme (where n is the number
     * of users in the multi-user Ind-CPA game of this adversary). The i-th
     * ciphertext should correspond to the generator and the i-th public key that
     * were supplied in the latest init call.
     * <p>
     * <b>IMPORTANT NOTE</b>: This adversary will only work correctly if the public
     * keys you gave in the init() method are exactly the second arguments of the
     * DDH challenges you queried the last time from the rerandomization oracle.
     * This means: when you call init(generator, publicKeys), then publicKeys must
     * be an array of the n elements g^(d_1), ..., g^(d_n) which come from the
     * rerandomized DDH challenges (g, g^(d_1), g^(e_1), g^(f_1)), ..., (g, g^(d_n),
     * g^(e_n), g^(f_n)) (<b>in exactly this order</b>) you received from your last
     * rerandomizationOracle.rerandomizeChallenge call, where n is the number of
     * users returned by getNumberUsers().
     * 
     * @param ciphertexts an array of n possible ciphertext of Elgamal's PKE scheme.
     *                    Look up the method encrypt of the class ElgamalPKEScheme
     *                    to see how ciphertexts should be constructed. The i-the
     *                    ciphertext must correspond to the i-th public key given in
     *                    the init call and should encrypt one of the messages
     *                    message0, message1 which were contained in the i-th
     *                    CandidateMessagePair returned by the latest
     *                    getCandidateMessages call.
     *                    <p>
     *                    Note, that all ciphertexts must simultaneously encrypt
     *                    message_b of their corresponding CandidateMessagePair
     *                    (where b = 0 or 1).
     * @return If in the init call n uniformly and independently distributed public
     *         keys have been supplied, and if for each i = 1, ..., n, the i-th
     *         ciphertext encrypts message_b of the i-th Candidate Message pair
     *         returned by getCandidateMessages, then this method has a
     *         non-negligible advantage in returning b. If one of the above
     *         conditions does not hold, then this method will return 0 or 1 without
     *         any guarantees of correctness.
     */
    int solveIndCPAChallenge(ElgamalCiphertext[] ciphertexts);
}
