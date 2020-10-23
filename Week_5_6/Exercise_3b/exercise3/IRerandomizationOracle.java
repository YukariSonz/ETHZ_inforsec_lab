package students.exercise3;

import students.exercise2.DDHChallenge;

/**
 * This class gives access to an oracle which rerandomizes DDH Challenges.
 * <p>
 * Use this class in Exercise 3.b) to rerandomize the DDH Challenge you are
 * given there.
 * <p>
 * <b>IMPORTANT NOTE</b>: Use exactly the group elements of the DDH challenges
 * rerandomized by this Rerandomization oracle as public keys for the adversary
 * in exercise 3.b). Don't rerandomize the DDH Challenge yourself in exercise
 * 3.b)!
 */
public interface IRerandomizationOracle {
    /**
     * Rerandomizes the given DDH challenge. On input a number n and an original DDH
     * Challenge, this method returns n new DDH Challenges. Those challenges use the
     * same generator as the original challenge and are honestly generated iff the
     * original challenge was honestly generated. I.e., if the original challenge is
     * of the form (g, g^x, g^y, g^z) and a returned DDH Challenge is of the form
     * (g, g^d, g^e, g^f), then it holds: z = x * y iff f = d * e. Other than that,
     * this method guarantees that the second and third group elements of all
     * returned DDH challenges are drawn uniformly and independently at random.
     * I.e., the exponents d_1, ..., d_n, e_1, ..., e_n of all returned DDH
     * challenges (g, g^(d_i), g^(e_i), g^(f_i)) are drawn uniformly and
     * independently at random from {0, ..., q - 1} where q is the order of the
     * group.
     * <p>
     * <b>IMPORTANT NOTE</b>: Use exactly the group elements g^(d_1), ..., g^(d_n)
     * as public keys for the adversary in exercise 3.b). Don't rerandomize the DDH
     * Challenge yourself in exercise 3.b)!
     * 
     * 
     * @param numberOfRerandomizations The number n of rerandomized DDHChallenges
     *                                 which shall be returned.
     * @param originalChallenge        The original DDH challenge which shall be
     *                                 rerandomized. The returned DDH challenges
     *                                 will be honestly generated iff the given
     *                                 originalChallenge was honestly generated.
     * @return Returns an array of size n where n = numberOfRerandomizations. The
     *         array consists of n rerandomized DDH Challenges which are honestly
     *         generated iff originalChallenge is honestly generated.
     * 
     * @throws NullPointerException     will be thrown if originalChallenge = null.
     * @throws IllegalArgumentException will be thrown if numberOfRerandomizations
     *                                  is negative or if one of the group elements
     *                                  of originalChallenge is not a valid group
     *                                  element.
     */
    DDHChallenge[] rerandomizeChallenge(int numberOfRerandomizations, DDHChallenge originalChallenge)
            throws IllegalArgumentException;
}
