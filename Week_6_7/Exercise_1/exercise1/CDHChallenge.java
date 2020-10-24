package students.exercise1;

import students.IGroupElement;

/**
 * This class is a container object for a Computational Diffie-Hellman challenge
 * tuple. A CDH tuple consists of three group elements: a generator g, a second
 * element g^x and a third group element g^y. A CDH tuple represents the problem
 * of computing the product of the exponents x and y in the exponent of g. A
 * correct solution to a CDH challenge tuple is a group element g^(x*y).
 * <p>
 * Instances of this class are NOT immutable.
 * 
 * @author Akin
 */
public class CDHChallenge {
    /**
     * Creates a new CDH challenge tuple. The entries of the new tuple will be
     * empty, i.e. null.
     */
    public CDHChallenge() {
    }

    /**
     * A generator of the group. This group element will be used as encoding of 1.
     */
    public IGroupElement generator;
    /**
     * A group element of the form g^x, where g is the generator in this tuple.
     * Usually, g^x was drawn uniformly random from the group.
     */
    public IGroupElement groupElementX;
    /**
     * A group element of the form g^y, where g is the generator in this tuple.
     * Usually, g^y was drawn uniformly random from the group.
     */
    public IGroupElement groupElementY;
}
