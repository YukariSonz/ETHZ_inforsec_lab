package students.exercise3;

import students.exercise2.DDHChallenge;

/**
 * An interface for TIGHT Reductions from the DDH problem to the Multi-User
 * Ind-CPA security of Elgamal's PKE scheme.
 * <p>
 * Instances who implement this interface are given a DDH challenge tuple and an
 * adversary for the Multi-User Ind-CPA security game of Elgamal's PKE scheme
 * and have to decide whether the DDH challenge tuple was honestly generated.
 * 
 * @author Akin
 */
public interface IDDHMultiUserIndCPAElgamalReduction {
    /**
     * This method shall decide whether the given DDH challenge tuple was honestly
     * generated. A DDH challenge tuple consists of four group elements (g, g^x,
     * g^y, g^z). If it was honestly generated, then z equals x * y. In this case,
     * this method should return true. If it was randomly generated, then z was
     * drawn randomly and is independent of x and y. In this case this method should
     * return false. In each case, this method should implement a TIGHT reduction.
     * I.e., this method may call the method solveIndCPAChallenge of the given
     * adversary at most once.
     * <p>
     * <b>IMPORTANT NOTE</b>: The adversary is only guaranteed to work correctly if
     * the public keys which it receives in its init() call are exactly the second
     * arguments of the DDH challenges you queried the last time from the
     * rerandomization oracle. This means: if you call init(generator, publicKeys),
     * then publicKeys must be an array of the n elements g^(d_1), ..., g^(d_n)
     * which come from the rerandomized DDH challenges (g, g^(d_1), g^(e_1),
     * g^(f_1)), ..., (g, g^(d_n), g^(e_n), g^(f_n)) (<b>in exactly this order</b>)
     * you received from your last rerandomizationOracle.rerandomizeChallenge call,
     * where n is the number of users returned by getNumberUsers(). Do not
     * rerandomize the given ddhChallenge yourself!
     * 
     * @param ddhChallenge          a DDHChallenge which contains the four group
     *                              elements (g, g^x, g^y, g^z). g is a generator of
     *                              the group and usually an encoding of one. The
     *                              exponents a and b are always drawn uniformly and
     *                              independently at random. If ddhChallenge was
     *                              generated honestly, then z = x * y. Otherwise, z
     *                              was drawn uniformly and independently at random.
     * @param adversary             an adversary for the Multi-User Ind-CPA security
     *                              game of Elgamal's PKE scheme. Its
     *                              solveIndCPAChallenge method should be used at
     *                              most once. Note that this adversary is only
     *                              guaranteed to output a correct value if the
     *                              public keys -- it receives in its init() call --
     *                              are exactly the second arguments of the DDH
     *                              challenges you queried the last time from the
     *                              rerandomization oracle.
     * @param rerandomizationOracle A rerandomization oracle which you must use to
     *                              rerandomize ddhChallenge. The adversary will
     *                              only output a correct value if it is
     *                              initialized with public keys which come from the
     *                              last call of
     *                              rerandomizationOracle.rerandomizeChallenge.
     * @return true, iff ddhChallenge was honestly generated, i.e, iff z = x * y.
     *         False, otherwise.
     */
    boolean decideDDH(DDHChallenge ddhChallenge, IElgamalMultiUserIndCPAAdversary adversary,
            IRerandomizationOracle rerandomizationOracle);
}
