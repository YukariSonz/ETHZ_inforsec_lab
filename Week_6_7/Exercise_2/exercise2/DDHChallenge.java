package students.exercise2;

import students.IGroupElement;

/**
 * This class is a container object for a Decisional Diffie-Hellman challenge
 * tuple.
 * <p>
 * A DDH tuple consists of four group elements: a generator g, a second element
 * g^x, a third group element g^y and a fourth group element g^z. A DDH tuple
 * represents the problem of deciding whether the exponent of the fourth group
 * element is the product of the exponents of the second and third element.
 * <p>
 * I.e., a DDH tuple represents the problem of deciding whether z equals x * y
 * or if z was sampled uniformly and independently of x and y at random. When
 * given a DDH challenge (g, g^x, g^y, g^z) from a DDH challenger there is a 50%
 * probability, that (g, g^x, g^y, g^z) was <b>sampled honestly</b>, i.e., a and
 * b were drawn independently and uniformly at random and z = xy, and a 50%
 * probability, that (g, g^x, g^y, g^z) was <b>sampled randomly</b>, i.e., x, y
 * and z were all drawn uniformly and independently at random.
 * <p>
 * A correct solution for this DDH tuple is a boolean value which is true iff
 * this tuple was sampled honestly, i.e., iff z = x * y.
 * <p>
 * Instances of this class are NOT immutable.
 * 
 * @author Akin
 */
public class DDHChallenge {
    /**
     * Creates a new DDH challenge tuple. The entries of the new tuple will be
     * empty, i.e. null.
     */
    public DDHChallenge() {
    }

    /**
     * A generator of the group. Usually an encoding of one.
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
    /**
     * A group element of the form g^z, where g is the generator in this tuple. This
     * DDH tuple was sampled honestly iff z = x * y. If this DDH tuple was not
     * sampled honestly, then g^z was drawn uniformly from the group.
     */
    public IGroupElement groupElementZ;
}
