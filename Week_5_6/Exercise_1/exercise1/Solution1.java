package students.exercise1;

import students.IGroupElement;
import students.elgamal.ElgamalCiphertext;
import students.exercise1.CDHChallenge;
import students.exercise1.ICDHOwCPAElgamalReduction;
import students.exercise1.IElgamalOwCPAAdversary;

import java.math.BigInteger;
import java.security.SecureRandom;

import static students.Helper.getRandomBigInteger;

/**
 * You can use this method.
 */
import static students.Helper.getRandomBigInteger;


//import students.elgamal.ElgamalPKEScheme;
/**
 * Implement your solution to Exercise 1 in this class.
 */
public class Solution1 implements ICDHOwCPAElgamalReduction {

    @Override
    public IGroupElement solveCDH(CDHChallenge cdhChallenge, IElgamalOwCPAAdversary adversary) {

        /**
         * Implement your solution here. You need to compute g^(x*y), where g, g^x and
         * g^y are determined by cdhChallenge.
         * 
         * You can use adversary for computing g^(xy). Note, that your reduction must be
         * TIGHT. This means, you may call the method
         * adversary.extractMessage(ciphertext) at most once and your solution must
         * succeed whenever the adversary succeeds.
         */

        /**
         * You can use the randomness of this random number generator.
         */
        
         
        IGroupElement generator = cdhChallenge.generator.clone();
        IGroupElement g_x = cdhChallenge.groupElementX.clone();
        IGroupElement g_y = cdhChallenge.groupElementY.clone();
        
        //Setup
        
        
        SecureRandom RNG = new SecureRandom();
        BigInteger r = getRandomBigInteger(RNG, generator.getGroupOrder()); //Secret Key
        IGroupElement c = generator.power(r);    //PublicKey
        //Encrypt
        ElgamalCiphertext ciphertext = new ElgamalCiphertext();
        //IGroupElement message = generator.power(r);
        ciphertext.c0 = g_y;
        ciphertext.c1 = g_x; // Can be arbitrary, as long as in group G
        
        adversary.init(generator, g_x);
        IGroupElement result = adversary.extractMessage(ciphertext); //Origional Message  
        
        IGroupElement g_xy = ciphertext.c1.multiply(result.invert());

        /**
         * You need to return g^(xy) here.
         */
        return g_xy;
    }
}
