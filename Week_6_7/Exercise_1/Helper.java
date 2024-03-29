package students;

import java.math.BigInteger;
import java.util.Random;

/**
 * A helper class which contains a helpful function to sample random BigIntegers
 * of a specific size.
 * 
 * @author Akin
 *
 */
public class Helper {
	/**
	 * Returns a random BigInteger between 0 and max-1
	 * 
	 * @param RNG a random number generator whose randomness shall be used.
	 * @param max An exclusive upper bound for the random number which shall be
	 *            sampled. This argument must be positive!
	 * @return returns a BigInteger which is sampled from the uniform distribution
	 *         of the set {0, ..., max - 1}.
	 */
	public static BigInteger getRandomBigInteger(Random RNG, BigInteger max) {
		BigInteger next = new BigInteger(max.bitLength(), RNG);
		while (next.compareTo(max) >= 0)
			next = new BigInteger(max.bitLength(), RNG);
		return next;
	}
}
