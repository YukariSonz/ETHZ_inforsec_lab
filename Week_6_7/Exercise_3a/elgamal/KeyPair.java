package students.elgamal;

/**
 * Instances of this class encapsulate a Pair of a Public Key (of type P) and a
 * Secret Key (of type S) for a public key cryptographic scheme.
 * 
 * This class is not immutable.
 * 
 * @author Akin
 * 
 * @param P the type of the public key.
 * @param S the type of the secret key.
 */
public class KeyPair<P, S> {

	/**
	 * A public key for a cryptographic public key-scheme. This public key
	 * corresponds to the secret key in this KeyPair.
	 */
	public P publicKey;
	/**
	 * A secret key for for a cryptographic public key-scheme. This secret key
	 * corresponds to the public key in this KeyPair.
	 */
	public S secretKey;

	/**
	 * This constructor will create an empty public key-secret key pair. That is,
	 * both fields, PublicKey and SecretKey, are null.
	 */
	public KeyPair() {
	}
}