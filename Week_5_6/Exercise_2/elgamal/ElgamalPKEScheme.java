package students.elgamal;

import static students.Helper.getRandomBigInteger;

import java.math.BigInteger;
import java.security.SecureRandom;

import students.IGroupElement;

/**
 * This class implements Elgamal's PKE Scheme which uses the IGroupElement
 * interface for its group computations.
 * 
 * @author Akin
 */
public class ElgamalPKEScheme {

    /**
     * According to the Java Documentation, this is a cryptographically strong
     * random number generator.
     */
    private SecureRandom RNG = new SecureRandom();

    /**
     * Takes a generator of a group and returns a pair of a public and a secret key.
     * 
     * @param generator A generator of the group. This group element will be used as
     *                  encoding of 1.
     * @return Returns an object which contains a public key and a corresponding
     *         secret key.
     */
    public KeyPair<IGroupElement, BigInteger> setup(IGroupElement generator) {
        KeyPair<IGroupElement, BigInteger> pair = new KeyPair<IGroupElement, BigInteger>();
        pair.secretKey = getRandomBigInteger(RNG, generator.getGroupOrder());
        pair.publicKey = generator.power(pair.secretKey);
        return pair;
    }

    /**
     * Encrypts the message with respect to the group generator and the public key.
     * 
     * @param generator A generator of the group. This group element will be used as
     *                  encoding of 1.
     * @param publicKey A group element which represents a public key with respect
     *                  to the generator.
     * @param message   A group element which shall be encrypted.
     * @return Returns an ElgamalCiphertext which consists of two generic group
     *         elements C0 and C1. The first element is an r-th power of the
     *         generator, while the second element is the product of an r-th power
     *         of the public key times the message. r is a random number which will
     *         be drawn by the Encrypt method.
     */
    public ElgamalCiphertext encrypt(IGroupElement generator, IGroupElement publicKey, IGroupElement message) {
        ElgamalCiphertext ciphertext = new ElgamalCiphertext();
        BigInteger r = getRandomBigInteger(RNG, generator.getGroupOrder());
        ciphertext.c0 = generator.power(r);
        ciphertext.c1 = publicKey.power(r).multiply(message);
        return ciphertext;
    }

    /**
     * Decrypts a ciphertext.
     * 
     * @param secretKey  A secret key which should correspond to the public key
     *                   which was used at encryption.
     * @param ciphertext A ciphertext of the Elgamal PKE scheme. Both fields, C0 and
     *                   C1, of the ciphertext may not be null!
     * @return a group element which is the plaintext which was encrypted by the
     *         given ciphertext.
     */
    public IGroupElement decrypt(BigInteger secretKey, ElgamalCiphertext ciphertext) {
        return ciphertext.c1.multiply(ciphertext.c0.power(secretKey.negate()));
    }
}
