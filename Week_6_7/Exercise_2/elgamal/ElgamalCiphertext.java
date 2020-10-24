package students.elgamal;

import students.IGroupElement;

/**
 * Instances of this class represent ciphertexts in Elgamal's PKE scheme.
 * 
 * A ciphertext c = (c0, c1) consists of two group elements.
 * 
 * This class is not immutable.
 * 
 * @author Akin
 *
 */
public class ElgamalCiphertext {

    /**
     * This constructor will create an empty ciphertext. That is, both fields, C0
     * and C1, are null.
     */
    public ElgamalCiphertext() {

    }

    /**
     * This group element should be of the form g^r, where g is an encoding of ONE
     * and r is a random big integer.
     */
    public IGroupElement c0;
    /**
     * This group element should be of the form pk^r * m, where pk is a public key
     * of Elgamal's PKE scheme and m the message which is to be encrypted.
     */
    public IGroupElement c1;
}