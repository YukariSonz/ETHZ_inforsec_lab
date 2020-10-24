package students.exercise1;

import students.IGroupElement;
import students.elgamal.ElgamalCiphertext;

/**
 * An interface for an adversary in the Ow-CPA security game of Elgamal's PKE
 * scheme.
 * <p>
 * An adversary who implements this interface will be state-based and can be
 * used to extract plaintexts from ciphertexts in the Ind Cpa game.
 * <p>
 * For this end, the methods init and extractMessage must be called in this
 * order. If those methods are not called in the correct order or if invalid
 * group elements have been given to the adversary, his response in
 * extractMessage will be erroneous.
 * 
 * @author Akin
 */

public interface IElgamalOwCPAAdversary {
    /**
     * Call this method to start an Ow-CPA game with this adversary. The adversary
     * will save a copy of the given Generator and PublicKey.
     * <p>
     * Calling this method a second time will cause this instance to overwrite it
     * last saved values.
     * <p>
     * If one of the both inputs is NOT a valid group element, then this method will
     * do nothing (the adversary will not save any values).
     * 
     * @param generator A generator of the generic group which encodes ONE. This
     *                  instance will save a cope of Generator.
     * @param publicKey A public key of Elgamal's PKE scheme which corresponds to
     *                  the given generator.
     */
    void init(IGroupElement generator, IGroupElement publicKey);

    /**
     * Call this method after you have called init. This method will return a group
     * element which is the message of the given ciphertext if this adversary can
     * successfully decrypt the given ciphertext.
     * <p>
     * Note, that an advantage in the Ow-CPA security game is only guaranteed to
     * work successfully -- with a non-negl. advantage -- if the message is he
     * supposed to extract was sampled uniformly and independently at random. This
     * means, for a correct application of this adversary, the message must be
     * independent of the public key and encryption randomness (that is c0 of the
     * given ciphertext) which are given to these adversary.
     * 
     * @param ciphertext a possible ciphertext of Elgamal's PKE scheme. Look up the
     *                   method Encrypt of the class ElgamalPKEScheme to see how
     *                   ciphertext should be constructed.
     * @return if init has never been called or if this adversary is not able to
     *         successfully decrypt the given ciphertext, this method will return
     *         null. If init has been called before with two valid group elements,
     *         and if the given ciphertext can be an Elgamal PKE ciphertext with
     *         respect to the generator and public key given to the init method,
     *         then this method will return a group element which is the message
     *         encrypted by the given ciphertext.
     */
    IGroupElement extractMessage(ElgamalCiphertext ciphertext);
}
