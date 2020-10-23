package students.exercise3;

import java.security.SecureRandom;
import java.math.BigInteger;

import students.exercise2.DDHChallenge;
import students.exercise3.IDDHRerandomizer;

import students.IGroupElement;

/**
 * You can use this method in Exercise 3.a.
 */
import static students.Helper.getRandomBigInteger;

/**
 * Implement your solutions to Exercise 3.a in this class.
 */
public class Solution3a implements IDDHRerandomizer {
    @Override
    public DDHChallenge[] rerandomize(int numberOfGames, DDHChallenge ddhChallenge, SecureRandom RNG) {
        /**
         * Implement your solution to Exercise 3.1 here.
         */

        DDHChallenge[] rerandomizedChallenges = new DDHChallenge[numberOfGames];

        /**
         * You need to rerandomize ddhChallenge. Use for this task, the randomness from
         * RNG. Don't use any other randomness.
         */
         
        IGroupElement generator = ddhChallenge.generator.clone();
        IGroupElement g_x = ddhChallenge.groupElementX.clone();
        IGroupElement g_y = ddhChallenge.groupElementY.clone();
        IGroupElement g_z = ddhChallenge.groupElementZ.clone();
        // BigInteger big = new BigInteger("10");
        // if (generator.getGroupOrder().compareTo(big) == -1){
        //   System.out.println(generator.getGroupOrder());
        // }
        

        /**
         * You must return here an array of DDH Challenges (g, g^(d_1), g^(e_1),
         * g^(f_1)), ..., (g, g^(d_n), g^(e_n), g^(f_n)) s.t. we have for each i = 1,
         * ..., n:
         * 
         * (g, g^(d_i), g^(e_i), g^(f_i)) is honestly generated, if (g, g^x, g^y, g^z)
         * was honestly generated. If z =/= x * y, then g^(f_i) must be sampled
         * uniformly at random from the group and independently from g^(d_i) and
         * g^(e_i).
         * 
         * In each case, g^(d_i) and g^(e_i) must be sampled uniformly and independently
         * at random from the group.
         */
         

        for (int i = 0; i < numberOfGames; i++){
          //Something goes here
          boolean toDo = true;
          DDHChallenge ddh = new DDHChallenge();
          ddh.generator = generator;
          
          IGroupElement g_x_new = ddhChallenge.groupElementX.clone();
          IGroupElement g_y_new = ddhChallenge.groupElementY.clone();
          IGroupElement g_z_new = ddhChallenge.groupElementZ.clone();
          
          BigInteger u1 = getRandomBigInteger(RNG, generator.getGroupOrder());
          BigInteger u2 = getRandomBigInteger(RNG, generator.getGroupOrder());
          BigInteger v = getRandomBigInteger(RNG, generator.getGroupOrder());
          
          IGroupElement gu1 = generator.clone();
          IGroupElement gu2 = generator.clone();
          IGroupElement gu12 = generator.clone();
          gu1 = gu1.power(u1);
          gu2 = gu2.power(u2);
          gu12 = gu12.power(u1.multiply(u2));
          
          IGroupElement yu1 = ddhChallenge.groupElementY.clone();
          IGroupElement xvu2 = ddhChallenge.groupElementX.clone();
          
          yu1 = yu1.power(u1);
          xvu2 = xvu2.power(v.multiply(u2));
          
          // BigInteger factorX = getRandomBigInteger(RNG, generator.getGroupOrder());
          // BigInteger factorY = getRandomBigInteger(RNG, generator.getGroupOrder());
          
          // g_x_new = g_x_new.power(factorX);
          // g_y_new = g_y_new.power(factorY);
          // BigInteger factorZ = factorX.multiply(factorY);
          

          // g_z_new = g_z_new.power(factorZ);
          g_x_new = g_x_new.power(v).multiply(gu1);
          g_y_new = g_y_new.multiply(gu2);
          g_z_new = g_z_new.power(v).multiply(gu12).multiply(yu1).multiply(xvu2);
          

            
          ddh.groupElementX = g_x_new;
          ddh.groupElementY = g_y_new;
          ddh.groupElementZ = g_z_new;
          
          rerandomizedChallenges[i] = ddh;
        }
        return rerandomizedChallenges;
    }

}