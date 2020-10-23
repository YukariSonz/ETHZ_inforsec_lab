package students.exercise2;

/**
 * An interface for TIGHT Reductions from the DDH problem to the Ind-CPA
 * security of Elgamal's PKE scheme.
 * <p>
 * Instances who implement this interface are given a DDH challenge tuple and an
 * adversary for the Ind CPA security game of Elgamal's PKE scheme and have to
 * decide whether the DDH challenge tuple was honestly generated.
 * 
 * @author Akin
 */
public interface IDDHIndCPAElgamalReduction {
    /**
     * This method shall decide whether the given DDH challenge tuple was honestly
     * generated. A DDH challenge tuple consists of four group elements (g, g^x,
     * g^y, g^z). If it was honestly generated, then z equals x * y. In this case,
     * this method should return true. If it was NOT honestly generated, then z was
     * drawn randomly and is independent of x and y. In this case this method should
     * return false. In each case, this method should implement a TIGHT reduction.
     * I.e., this method may call the method solveIndCPAChallenge of the given
     * adversary at most once.
     * 
     * @param ddhChallenge a DDHChallenge which contains the four group elements (g,
     *                     g^x, g^y, g^z). g is a generator of the group and usually
     *                     an encoding of one. The exponents x and y are always
     *                     drawn uniformly and independently at random. If
     *                     ddhChallenge was generated honestly, then z = x * y.
     *                     Otherwise, z was drawn uniformly and independently at
     *                     random.
     * @param adversary    an adversary for the Ind-CPA security game of Elgamal's
     *                     PKE scheme. Its solveIndCPAChallenge method should be
     *                     used at most once.
     * @return true iff ddhChallenge was honestly generated, i.e iff z = x * y.
     *         False, otherwise.
     */
    boolean decideDDH(DDHChallenge ddhChallenge, IElgamalIndCPAAdversary adversary);
}
