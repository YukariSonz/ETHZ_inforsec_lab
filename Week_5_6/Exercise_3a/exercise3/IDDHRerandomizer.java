package students.exercise3;

import java.security.SecureRandom;

import students.exercise2.DDHChallenge;

/**
 * An interface for rerandomizing DDH tuples
 * 
 * @author Akin
 */
public interface IDDHRerandomizer {
    /**
     * This method shall rerandomize a given DDH challenge. I.e., given a challenge
     * tuple (g, g^x, g^y, g^z), it shall return tuples of the form (g, g^d, g^e,
     * g^f) s.t. two things hold:
     * <p>
     * 1. If z = x * y, then it must hold f = e * d.
     * <p>
     * 2. However, if z is not equal to x * y, then f must be drawn uniformly at
     * random and independently of d and e.
     * <p>
     * In both cases, the exponents d and e should always be distributed uniformly
     * and independently at random.
     * <p>
     * This rerandomization method must be state-less. I.e., its output values should
     * only depend from ddhChallenge and the randomness given by RNG.
     * 
     * @param numberOfTuples The number n of tuples that this function must return.
     *                       In particular, the length of the output array must
     *                       equal this value.
     * @param ddhChallenge   A DDH challenge tuple which shall be rerandomized.
     * @param RNG            the random number generator this method shall use. This
     *                       method must not use other randomness from other
     *                       sources. It is expected that two calls of this method
     *                       return the same values when they are given the same
     *                       ddhChallenge and RNG where in both cases RNG has been
     *                       initialized with the same seed.
     * @return an array of DDHChallenges (g, g^(d_1), g^(e_1), g^(f_1)), ..., (g,
     *         g^(d_n), g^(e_n), g^(f_n)) s.t. we have for each (g, g^(d_i),
     *         g^(e_i), g^(f_i)):
     *         <p>
     *         (g, g^(d_i), g^(e_i), g^(f_i)) is honestly generated, if (g, g^x,
     *         g^y, g^z) was honestly generated. If z =/= x * y, then g^(f_i) must
     *         be sampled uniformly at random from the group and independently from
     *         g^(d_i) and g^(e_i).
     *         <p>
     *         In each case, g^(d_i) and g^(e_i) must be sampled uniformly and
     *         independently at random from the group.
     */
    DDHChallenge[] rerandomize(int numberOfTuples, DDHChallenge ddhChallenge, SecureRandom RNG);
}
