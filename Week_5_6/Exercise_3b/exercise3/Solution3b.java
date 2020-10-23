package students.exercise3;

import java.security.SecureRandom;

import students.IGroupElement;
import students.elgamal.ElgamalCiphertext;
import students.exercise2.CandidateMessagePair;
import students.exercise2.DDHChallenge;
import students.exercise3.IElgamalMultiUserIndCPAAdversary;

/**
 * Implement your solutions to Exercise 3.b) in this class.
 */
public class Solution3b implements IDDHMultiUserIndCPAElgamalReduction {
    @Override
    public boolean decideDDH(DDHChallenge ddhChallenge, IElgamalMultiUserIndCPAAdversary adversary,
            IRerandomizationOracle rerandomizationOracle) {
        /**
         * Implement your solution here. You need to decide whether z = x * y, where g,
         * g^x, g^y and g^z are determined by ddhChallenge.
         * 
         * You can use adversary for deciding this. Note, that your reduction must be
         * TIGHT. This means, you may call the method
         * adversary.solveIndCPAChallenge(ciphertexts) at most once.
         * 
         * IMPORTANT: Make sure that the public keys given to the adversary come from
         * the DDH challenges rerandomized by rerandomizationOracle! Look up the
         * documentation of adversary and rerandomizationOracle for more details!
         */

        /**
         * You can use the randomness of this random number generator.
         */
        IGroupElement generator = ddhChallenge.generator.clone();
        int numberOfUsers = adversary.getNumberUsers();
        
        SecureRandom RNG = new SecureRandom();
        
        DDHChallenge[] rerandomizeChallenges = rerandomizationOracle.rerandomizeChallenge(numberOfUsers, ddhChallenge);
        
        IGroupElement[] publicKeyList = new IGroupElement[numberOfUsers];
        
        IGroupElement[] gyList = new IGroupElement[numberOfUsers];
        
        IGroupElement[] gzList = new IGroupElement[numberOfUsers];
        
        for (int i = 0; i < numberOfUsers; i++){
          IGroupElement publicKey = rerandomizeChallenges[i].groupElementX;
          IGroupElement gy = rerandomizeChallenges[i].groupElementY;
          IGroupElement gz = rerandomizeChallenges[i].groupElementZ;
          publicKeyList[i] = publicKey;
          gyList[i] = gy;
          gzList[i] = gz;
        }
        
        adversary.init(generator, publicKeyList);
        int randomNumber = RNG.nextInt(2);
        
        
        adversary.init(generator, publicKeyList);
        CandidateMessagePair[] messagesList = adversary.getCandidateMessages();
        
        ElgamalCiphertext[] ciphertextList = new ElgamalCiphertext[numberOfUsers];
        
        
        for (int k = 0; k < numberOfUsers; k++){
          //randomNumber = RNG.nextInt(2);
          IGroupElement gy = gyList[k];
          IGroupElement gz = gzList[k];
          CandidateMessagePair messages = messagesList[k];
          
          IGroupElement messageChosen = (IGroupElement) messages.getMessage(randomNumber);
          ElgamalCiphertext ciphertext = new ElgamalCiphertext();
          ciphertext.c0 = gy;
          ciphertext.c1 = gz.multiply(messageChosen);
          ciphertextList[k] = ciphertext;
        }
        
        int result = adversary.solveIndCPAChallenge(ciphertextList);
        
        if (result == randomNumber){
          return true;
        }
        else{
          return false;
        }
        //IGroupElement message_0  = (IGroupElement) message.getMessage(0);
        //IGroupElement message_1  = (IGroupElement) message.getMessage(1);
        
        // IGroupElement messageChosen = (IGroupElement) message.getMessage(randomNumber);
        // //Encrypt
        // ElgamalCiphertext ciphertext = new ElgamalCiphertext();
        // ciphertext.c0 = g_y;
        // ciphertext.c1 = g_z.multiply(messageChosen); // Can be arbitrary, as long as in group G
        
        

        /**
         * You need to return here true iff ddhChallenge was honestly generated. I.e.,
         * if z = x * y, then you must return true here. Otherwise, you must return
         * false.
         */
        //return false;
    }

}
