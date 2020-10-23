package students.exercise2;

import java.security.SecureRandom;

import students.IGroupElement;
import students.elgamal.ElgamalCiphertext;
import students.exercise2.CandidateMessagePair;
import students.exercise2.DDHChallenge;
import students.exercise2.IDDHIndCPAElgamalReduction;
import students.exercise2.IElgamalIndCPAAdversary;

/**
 * Implement your solution to Exercise 2 in this class.
 */
public class Solution2 implements IDDHIndCPAElgamalReduction {

    @Override
    public boolean decideDDH(DDHChallenge ddhChallenge, IElgamalIndCPAAdversary adversary) {
        /**
         * Implement your solution here. You need to decide whether z = x * y, where g,
         * g^x, g^y and g^z are determined by ddhChallenge.
         * 
         * You can use adversary for deciding this. Note, that your reduction must be
         * TIGHT. This means, you may call the method
         * adversary.solveIndCPAChallenge(ciphertext) at most once.
         */

        /**
         * You can use the randomness of this random number generator.
         */
        IGroupElement generator = ddhChallenge.generator.clone();
        IGroupElement g_x = ddhChallenge.groupElementX.clone();
        IGroupElement g_y = ddhChallenge.groupElementY.clone();
        IGroupElement g_z = ddhChallenge.groupElementZ.clone();
        
        //Setup
        
        
        SecureRandom RNG = new SecureRandom();
        int randomNumber = RNG.nextInt(2);
        
        
        adversary.init(generator, g_x);
        CandidateMessagePair message = adversary.getCandidateMessages();
        //IGroupElement message_0  = (IGroupElement) message.getMessage(0);
        //IGroupElement message_1  = (IGroupElement) message.getMessage(1);
        
        IGroupElement messageChosen = (IGroupElement) message.getMessage(randomNumber);
        //Encrypt
        ElgamalCiphertext ciphertext = new ElgamalCiphertext();
        ciphertext.c0 = g_y;
        ciphertext.c1 = g_z.multiply(messageChosen); // Can be arbitrary, as long as in group G
        
        
        //IGroupElement g_xy = ciphertext.c1.multiply(result.invert());
        int results = adversary.solveIndCPAChallenge(ciphertext);
        

        
        if (results == randomNumber){
          return true;
        }
        else{
          return false;
        }

        /**
         * You need to return here true iff ddhChallenge was honestly generated. I.e.
         * iff z = x * y, then you must return true here. Otherwise, you must return
         * false.
         */
        //return false;
    }
}
