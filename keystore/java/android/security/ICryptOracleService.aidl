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
	 * @param algorithm the algorithm used for encryption (only used for symmetric encryption, for asymmetric keys this is derived from the key itself)
	 * @param padding the padding to use for encryption, see {@link Cipher#getInstance(String)}
	 * @param plainData the data to encrypt
	 * @param iv the algorithm iv, or null if none is needed for this mode of operation
	 * @return encrypted data
	 */
	byte[] encryptData(String alias, String algorithm, String padding, in byte[] plainData, in byte[] iv);
	
	/**
	 * decrypts data using a private key specified by it's alias
	 * @param alias the alias identifying the private key to use for decryption
	 * @param algorithm the algorithm used for decryption (only used for symmetric encryption, for asymmetric keys this is derived from the key itself) 
	 * @param padding the padding to use for decryption, see {@link Cipher#getInstance(String)}
	 * @param encryptedData the data to decrypt
	 * @param iv the algorithm iv, or null if none is needed for this mode of operation
	 * @return decrypted data
	 */
	byte[] decryptData(String alias, String algorithm, String padding, in byte[] encryptedData, in byte[] iv);
	
	/**
	 * signs data using a private key specified by it's alias
	 * @param alias the alias identifying the private key to use for signing
	 * @param algorithm the signature algorithm, {@see java.security.Signature}
	 * @param data the data to sign
	 * @return the signature
	 */
	byte[] sign(String alias, String algorithm, in byte[] data);
	
	/**
	 * verify a signature using a public key specified by it's alias
	 * @param alias the alias identifying the public key to use for verification
	 * @param algorithm the signature algorithm, {@see java.security.Signature}
	 * @param data the data that is supposed to be signed by the signature
	 * @param signature the signature that is supposed to sign the data
	 * @return true if the signature is valid for the given data
	 */
	boolean verify(String alias, String algorithm, in byte[] data, in byte[] signature);

	/**
	 * stores a certificate in the keystore
	 * @param alias the alias used for identifying this public key in further operations
	 * @param pemEncodedCert the byte data of the PEM encoded certificate
	 */	
	void storePublicCertificate(String alias, in byte[] pemEncodedCert);
	
	/**
	 * generates a symmetric key and stores it in the keystore
	 * @param alias the alias used for identifying the genreated key
	 * @param alias the algorithm the key will be used for ({@see javax.crypto.KeyFactory#getInstance(String)}) 
	 * @param keysize
	 */
   	void generateSymmetricKey(String alias, String algorithm, int keysize);
   	
   	/**
   	 * retrieves a symmetric key
   	 * @param alias the alias used for identifying the key
   	 * @param the algorithm the key will be used for
   	 * @return the encoded key data
   	 */
   	byte[] retrieveSymmetricKey(String alias, String algorithm);
   	
   	/**
   	 * stores a given symmetric key in the keystore
   	 * @param alias the alias used for identifying the key
   	 * @param key the encoded key
   	 */
   	void importSymmetricKey(String alias, in byte[] key);
   	
   	/**
   	 * removes a symmetric key from the keystore
   	 * @param alias the alias used for identifying the key
   	 */
   	void deleteSymmetricKey(String alias);

	/**
	 * generate a MAC with a given symmetric key for the input data
	 * @param alias the alias used for identifying the key
	 * @param algorithm the MAC algorithm ({@see javax.crypto.Mac#getInstance(String)})
	 * @param data the data to MAC
	 * @return the digest
	 */
   	byte[] mac(String alias, String algorithm, in byte[] data);
   	
   	/**
   	 * generate a key pair under the application control (eg. for use with DH)
   	 * @param alias the alias used for identifying the key
   	 * @param keyAlgorithm the key algorithm
   	 * @param keysize
   	 * @return encoded public key  
   	 */
   	byte[] generateKeyPair(String alias, String keyAlgorithm, int keysize);

   	
   	byte[] keyAgreementPhase(String alias, String keyAlgorithm, String agreementAlgorithm, in byte[] encodedPublicKey, boolean lastPhase);
}
