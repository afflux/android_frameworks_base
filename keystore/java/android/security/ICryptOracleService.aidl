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
	 * @returns encrypted data
	 */
	byte[] encryptData(String alias, String padding, in byte[] plainData);
	
	/**
	 * decrypts data using a private key specified by it's alias
	 * @param alias the alias identifying the private key to use for decryption
	 * @param padding the padding to use for decryption, see {@link Cipher#getInstance(String)}
	 * @param encryptedData the data to decrypt
	 * @returns decrypted data
	 */
	byte[] decryptData(String alias, String padding, in byte[] encryptedData);
}
