package students;

import java.math.BigInteger;

/**
 * Objects which implements this interface encapsulate basic operations a user
 * can do when interacting with an oracle of a generic group: Inversion,
 * multiplication, raising to the power of some exponent.
 * <p>
 * Instances of this interface are immutable. (The operations Multiply, Power
 * and Invert do not change an instance of this class.)
 * 
 * @author Akin
 *
 */
public interface IGroupElement {
    /**
     * Returns the order of the group to which this element belongs to.
     * 
     * @return the order of the corresponding group, i.e., the number of elements of
     *         the group.
     */
    BigInteger getGroupOrder();

    /**
     * Returns a new group element which encodes the sum of the exponents of this
     * group element and the other group element.
     * 
     * Calling this method will neither change this object nor the the given
     * argument!
     * 
     * @param otherElement A group element which shall be multiplied with this one.
     * @return the product of this element and the other element.
     * @throws IllegalArgumentException will be thrown if this element or the other
     *                                  group element has been illegally tampered.
     * @throws NullPointerException     will be thrown if the given argument is
     *                                  null.
     */
    IGroupElement multiply(IGroupElement otherElement) throws IllegalArgumentException, NullPointerException;

    /**
     * Returns a new group element which encodes the product of the given argument
     * and the exponent of this group element. Calling this method will neither
     * change this object nor the the given argument!
     * 
     * @param exponent A number which shall be multiplied with the number encoded by
     *                 this group element.
     * @return the k-th power of this group element, where k is the given exponent.
     * @throws IllegalArgumentException will be thrown if this element has been
     *                                  illegally tampered.
     * @throws NullPointerException     will be thrown if the given argument is
     *                                  null.
     */
    IGroupElement power(BigInteger exponent) throws IllegalArgumentException, NullPointerException;

    /**
     * Returns a new group element which encodes -k where k is the exponent of this
     * group element. This call should be identical to Power(-1). Calling this
     * method will not change this object!
     * 
     * @return a new group element h such that Multiply(this, h) should result in
     *         the neutral element.
     * @throws IllegalArgumentException will be thrown if this element has been
     *                                  illegally tampered.
     */
    IGroupElement invert() throws IllegalArgumentException;

    /**
     * Returns a deep copy of this group element.
     * 
     * @return a deep copy of this group element.
     */
    IGroupElement clone();

    /**
     * Returns iff this group element and the other group element decode the same
     * exponent.
     * 
     * @param groupElement the other group element which shall be checked for
     *                     equality of exponents.
     * @return true iff this group element or the other one encode the same
     *         exponent. false iff the other group element is null or the exponents
     *         of this group element and the other element are not equal.
     */
    boolean equals(IGroupElement groupElement);
}
