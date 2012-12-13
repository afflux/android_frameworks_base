package android.security;

/**
 * Caller is required to ensure that {@link KeyStore#unlock
 * KeyStore.unlock} was successful.
 *
 * @hide
 */
interface ICryptOracleService {
	/**
	 * encrypts data using a public key specified by it's alias
	 * @param alias the alias identifying the public key to use for encryption
	 * @param padding the padding to use for encryption, see {@link Cipher#getInstance(String)}
	 * @param plainData the data to encrypt
	 * @return encrypted data
	 */
	byte[] encryptData(String alias, String padding, in byte[] plainData);
	
	/**
	 * decrypts data using a private key specified by it's alias
	 * @param alias the alias identifying the private key to use for decryption
	 * @param padding the padding to use for decryption, see {@link Cipher#getInstance(String)}
	 * @param encryptedData the data to decrypt
	 * @return decrypted data
	 */
	byte[] decryptData(String alias, String padding, in byte[] encryptedData);
	
	/**
	 * signs data using a private key specified by it's alias
	 * @param alias the alias identifiying the private key to use for signing
	 * @param algorithm the signature algorithm, {@see java.security.Signature}
	 * @param data the data to sign
	 * @return the signature
	 */
	byte[] sign(String alias, String algorithm, in byte[] data);
	
	/**
	 * verify a signature using a public key specified by it's alias
	 * @param alias the alias identifiying the public key to use for verification
	 * @param algorithm the signature algorithm, {@see java.security.Signature}
	 * @param data the data that is supposed to be signed by the signature
	 * @param signature the signature that is supposed to sign the data
	 * @return true if the signature is valid for the given data
	 */
	boolean verify(String alias, String algorithm, in byte[] data, in byte[] signature);

	/**
	 * stores a certificate in the keystore
	 * @param alias the alias used for identifiying this public key in further operations
	 * @param pemEncodedCert the byte data of the PEM encoded certificate
	 */	
	void storePublicCertificate(String alias, in byte[] pemEncodedCert);
}
