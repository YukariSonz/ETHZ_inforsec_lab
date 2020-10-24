package students.exercise2;

/**
 * This object contains two candidate messages chosen by an Ind-CPA adversary.
 * <p>
 * Instances of this class will be returned by an IndCpaAdversary if one asks
 * for two candidate messages in the IND-CPA security game by calling
 * getCandidateMessages().
 * <p>
 * This class is not immutable.
 * 
 * @param M the type the messages have. For Elgamal's PKE scheme, M is
 *          IGroupElement.
 * 
 * @author Akin
 *
 */
public class CandidateMessagePair<M> {
	/**
	 * This constructor will create an empty pair of candidate messages. That is,
	 * both fields, Message0 and Message1, are null.
	 */
	public CandidateMessagePair() {
	}

	/**
	 * The first message of this pair.
	 */
	public M Message0;
	/**
	 * The second message of this pair.
	 */
	public M Message1;

	/**
	 * Returns one of the two candidate message.
	 * 
	 * @param index determines which message shall be returned.
	 * @return Message0 if index == 0, and Message1 if index = 1.
	 * @throws IllegalArgumentException will be thrown if index is neither 0 nor 1
	 */
	public M getMessage(int index) throws IllegalArgumentException {
		if (index == 0)
			return Message0;
		if (index == 1)
			return Message1;
		throw new IllegalArgumentException("index must be 0 or 1!");
	}
}
