
package android.security;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;

import java.io.Closeable;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Kjell Braden <kjell.braden@stud.tu-darmstadt.de>
 */
public final class CryptOracle {
    public enum UsageType {
        PUBLIC_ENCRYPT, PRIVATE_DECRYPT,
        PUBLIC_VERIFY, PRIVATE_SIGN,
        SECRET, AGREEMENT;
    }

    /*
     * The following code is taken from android.security.KeyChain, as it uses
     * the same binding mechanism
     */
    private final static class CryptOracleConnection implements Closeable {
        private final Context context;
        private final ICryptOracleService service;
        private final ServiceConnection serviceConnection;

        private CryptOracleConnection(Context context, ServiceConnection serviceConnection,
                ICryptOracleService service) {
            this.context = context;
            this.serviceConnection = serviceConnection;
            this.service = service;
        }

        @Override
        public void close() {
            this.context.unbindService(this.serviceConnection);
        }

        public ICryptOracleService getService() {
            return this.service;
        }
    }

    public final static class StringAliasNotFoundException extends Exception {
        private static final long serialVersionUID = -1722952359173012650L;
    }

    public static final String EXTRA_ALIAS = "alias";
    public static final String EXTRA_TYPE = "type";

    private static CryptOracleConnection bind(Context context) throws InterruptedException {
        if (context == null)
            throw new NullPointerException("context == null");
        ensureNotOnMainThread(context);
        final BlockingQueue<ICryptOracleService> q = new LinkedBlockingQueue<ICryptOracleService>(1);
        ServiceConnection cryptOracleServiceConnection = new ServiceConnection() {
            volatile boolean mConnectedAtLeastOnce = false;

            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                if (!this.mConnectedAtLeastOnce) {
                    this.mConnectedAtLeastOnce = true;
                    try {
                        q.put(ICryptOracleService.Stub.asInterface(service));
                    } catch (InterruptedException e) {
                        // will never happen, since the queue starts with one
                        // available slot
                    }
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
            }
        };
        boolean isBound = context.bindService(new Intent(ICryptOracleService.class.getName()),
                cryptOracleServiceConnection,
                Context.BIND_AUTO_CREATE);
        if (!isBound)
            throw new AssertionError("could not bind to KeyChainService");
        return new CryptOracleConnection(context, cryptOracleServiceConnection, q.take());
    }

    /**
     * create an intent to start a system activity that makes sure the given key
     * can be accessed and used for the given usage type
     * 
     * @param activity
     * @param alias
     * @param type
     * @return a startable intent, to be used with
     *         {@link Activity#startActivity(Intent)}
     */
    public static Intent createCheckAccessIntent(Activity activity, String alias, UsageType type) {
        Intent i = new Intent().setClassName("com.android.keychain",
                "com.android.keychain.manage.GrantKeyAccessActivity");
        i.putExtra(CryptOracle.EXTRA_ALIAS, alias);
        i.putExtra(CryptOracle.EXTRA_TYPE, type);
        // the PendingIntent is used to get calling package name
        i.putExtra(KeyChain.EXTRA_SENDER, PendingIntent.getActivity(activity, 0, new Intent(), 0));
        return i;
    }

    /**
     * @param ctx
     * @param alias identifier of the key to be used for decryption
     * @param algorithm
     * @param padding mode and padding specification, as described in
     *            {@link Cipher}
     * @param encryptedData the data to be decrypted
     * @param params algorithm iv, or null if the mode of operation does not
     *            require an IV
     * @return decrypted data
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws StringAliasNotFoundException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     */
    public static byte[] decryptData(Context ctx, String alias, String algorithm, String padding,
            byte[] encryptedData, IvParameterSpec params) throws KeyChainException,
            InterruptedException,
            InvalidKeySpecException, CertificateException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            StringAliasNotFoundException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        byte[] iv = null;
        if (params != null)
            iv = params.getIV();
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            return cryptOracleService.decryptData(alias, algorithm, padding, encryptedData, iv);
        } catch (RemoteException e) {
            extractRemotePrivkeyException(e);
            extractRemoteCryptException(e);
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * @param ctx
     * @param alias identifier of the key to be used for decryption
     * @param algorithm
     * @param padding mode and padding specification, as described in
     *            {@link Cipher}
     * @param data the data to be encrypted
     * @param params algorithm iv, or null if the mode of operation does not
     *            require an IV
     * @return encrypted data
     * @throws KeyChainException
     * @throws InterruptedException
     * @throws StringAliasNotFoundException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     */
    public static byte[] encryptData(Context ctx, String alias, String algorithm, String padding,
            byte[] data, IvParameterSpec params) throws KeyChainException, InterruptedException,
            InvalidKeySpecException, CertificateException, NoSuchAlgorithmException,
            NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, StringAliasNotFoundException {

        CryptOracleConnection cryptOracleConnection = bind(ctx);
        byte[] iv = null;
        if (params != null)
            iv = params.getIV();
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            return cryptOracleService.encryptData(alias, algorithm, padding, data, iv);
        } catch (RemoteException e) {
            extractRemotePubkeyException(e);
            extractRemoteCryptException(e);
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    private static void ensureNotOnMainThread(Context context) {
        Looper looper = Looper.myLooper();
        if ((looper != null) && (looper == context.getMainLooper()))
            throw new IllegalStateException(
                    "calling this from your main thread can lead to deadlock");
    }

    private static void extractRemoteCryptException(RemoteException e)
            throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            IllegalArgumentException {
        Throwable s0 = _extractRemoteException(e);

        if (s0 instanceof NoSuchPaddingException)
            throw (NoSuchPaddingException) s0;
        if (s0 instanceof IllegalBlockSizeException)
            throw (IllegalBlockSizeException) s0;
        if (s0 instanceof BadPaddingException)
            throw (BadPaddingException) s0;
        if (s0 instanceof IllegalArgumentException)
            throw (IllegalArgumentException) s0;
    }

    private static Throwable _extractRemoteException(RemoteException e) {
        Throwable[] suppressed = e.getSuppressed();
        if ((suppressed == null) || (suppressed.length == 0))
            return null;

        return suppressed[0];
    }

    private static void extractRemoteSignException(RemoteException e)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Throwable s0 = _extractRemoteException(e);

        if (s0 instanceof NoSuchAlgorithmException) // in sign / verify
            throw (NoSuchAlgorithmException) s0;
        if (s0 instanceof InvalidKeyException) // in sign / verify
            throw (InvalidKeyException) s0;
    }

    private static void extractRemotePubkeyException(RemoteException e)
            throws StringAliasNotFoundException, CertificateException {
        Throwable s0 = _extractRemoteException(e);
        if (s0 instanceof StringAliasNotFoundException)
            throw (StringAliasNotFoundException) s0;
        if (s0 instanceof CertificateException)
            throw (CertificateException) s0;
    }

    private static void extractRemoteSecretKeyException(RemoteException e)
            throws StringAliasNotFoundException, IllegalArgumentException {
        Throwable s0 = _extractRemoteException(e);
        if (s0 instanceof StringAliasNotFoundException)
            throw (StringAliasNotFoundException) s0;
        if (s0 instanceof IllegalArgumentException)
            throw (IllegalArgumentException) s0;
    }

    private static void extractRemotePrivkeyException(RemoteException e)
            throws StringAliasNotFoundException, InvalidKeySpecException {
        Throwable s0 = _extractRemoteException(e);
        if (s0 instanceof StringAliasNotFoundException)
            throw (StringAliasNotFoundException) s0;
        if (s0 instanceof InvalidKeySpecException)
            throw (InvalidKeySpecException) s0;
    }

    /**
     * Sign the given data with a private key identified by alias.
     * 
     * @param ctx
     * @param alias identifier of the private key to be used for signing
     * @param data the data to sign
     * @return the signature
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws StringAliasNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     */
    public static byte[] sign(Context ctx, String alias, String algorithm, byte[] data)
            throws InterruptedException, KeyChainException, InvalidKeyException,
            InvalidKeySpecException, NoSuchAlgorithmException, StringAliasNotFoundException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            return cryptOracleService.sign(alias, algorithm, data);
        } catch (RemoteException e) {
            extractRemotePrivkeyException(e);
            extractRemoteSignException(e);
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * store a certificate in the KeyChain
     * 
     * @param ctx
     * @param alias the alias used for identifiying this public key in further
     *            operations
     * @param cert the certificate to be stored
     * @throws CertificateEncodingException if the certificate could not be
     *             converted to PEM format
     * @throws IllegalArgumentException if the specified alias is already in use
     * @throws InterruptedException
     * @throws KeyChainException
     */
    public static void storePublicCertificate(Context ctx, String alias, Certificate cert)
            throws CertificateEncodingException, InterruptedException, IllegalArgumentException,
            KeyChainException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();

            byte[] pemEncodedCert = Credentials.convertToPem(cert);

            cryptOracleService.storePublicCertificate(alias, pemEncodedCert);
        } catch (RemoteException e) {
            Throwable s0 = _extractRemoteException(e);
            if (s0 instanceof IllegalArgumentException)
                throw (IllegalArgumentException) s0;

            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } catch (IOException e) {
            throw new CertificateEncodingException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * Verify the signature of data
     * 
     * @param ctx
     * @param alias identifier of the public key to be used for verification
     * @param data the signed data
     * @param signature the signature
     * @return true if the signature was correct
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws StringAliasNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     */
    public static boolean verify(Context ctx, String alias, String algorithm, byte[] data,
            byte[] signature) throws InterruptedException, KeyChainException, InvalidKeyException,
            CertificateException, NoSuchAlgorithmException, StringAliasNotFoundException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            return cryptOracleService.verify(alias, algorithm, data, signature);
        } catch (RemoteException e) {
            extractRemotePubkeyException(e);
            extractRemoteSignException(e);
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * generate a symmetric key and store it in the system keystore
     * 
     * @param ctx
     * @param alias identifier of the key for later use
     * @param algorithm the key algorithm to be used
     * @param keysize the key size
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws NoSuchAlgorithmException if the given algorithm is unkown
     * @throws IllegalArgumentException if the given alias is already in use
     */
    public static void generateSymmetricKey(Context ctx, String alias, String algorithm, int keysize)
            throws InterruptedException, KeyChainException, NoSuchAlgorithmException,
            IllegalArgumentException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            cryptOracleService.generateSymmetricKey(alias, algorithm, keysize);
        } catch (RemoteException e) {
            Throwable s0 = _extractRemoteException(e);
            if (s0 instanceof IllegalArgumentException)
                throw (IllegalArgumentException) s0;
            if (s0 instanceof NoSuchAlgorithmException)
                throw (NoSuchAlgorithmException) s0;

            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * retrieve a symmetric key from the keystore
     * 
     * @param ctx
     * @param alias identifier of the key
     * @param algorithm key type
     * @return a SecretKey with the algorithm set to the given key type
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws StringAliasNotFoundException if there is no key available with
     *             the given alias
     * @throws IllegalArgumentException if the algorithm is not available
     */
    public static SecretKey retrieveSymmetricKey(Context ctx, String alias, String algorithm)
            throws InterruptedException, KeyChainException, StringAliasNotFoundException,
            IllegalArgumentException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            byte[] encodedKey = cryptOracleService.retrieveSymmetricKey(alias, algorithm);

            return new SecretKeySpec(encodedKey, algorithm);
        } catch (RemoteException e) {
            extractRemoteSecretKeyException(e);
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * import a SecretKey object into the system keystore
     * 
     * @param ctx
     * @param alias identifier of the key for further usage
     * @param key the key to import
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws IllegalArgumentException if the given alias is already in use
     */
    public static void importSymmetricKey(Context ctx, String alias, SecretKey key)
            throws InterruptedException, KeyChainException, IllegalArgumentException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            byte[] encodedKey = key.getEncoded();
            cryptOracleService.importSymmetricKey(alias, encodedKey);
        } catch (RemoteException e) {
            Throwable s0 = _extractRemoteException(e);
            if (s0 instanceof IllegalArgumentException)
                throw (IllegalArgumentException) s0;

            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * delete a symmetric key from the system keystore
     * 
     * @param ctx
     * @param alias identifier of the key
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws StringAliasNotFoundException if there is no key available with
     *             the given alias
     */
    public static void deleteSymmetricKey(Context ctx, String alias)
            throws InterruptedException, KeyChainException, StringAliasNotFoundException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            cryptOracleService.deleteSymmetricKey(alias);
        } catch (RemoteException e) {
            Throwable s0 = _extractRemoteException(e);
            if (s0 instanceof StringAliasNotFoundException)
                throw (StringAliasNotFoundException) s0;

            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * generate a MAC (message authentication code) for a given message
     * 
     * @param ctx
     * @param alias identifier of the symmetric key to use for authentication
     * @param algorithm a mac algorithm type (see
     *            {@link javax.crypto.Mac#getInstance(String)
     *            Mac.getInstance(String)})
     * @param data data to authenticate
     * @see javax.crypto.Mac
     * @return an authenticated message digest
     * @throws InterruptedException
     * @throws KeyChainException
     * @throws NoSuchAlgorithmException if the algorithm is unknown
     * @throws InvalidKeyException if the key can't be used for this algorithm
     * @throws IllegalArgumentException if the key can't be used for this
     *             algorithm
     * @throws StringAliasNotFoundException if there is no key available with
     *             the given alias
     */
    public static byte[] mac(Context ctx, String alias, String algorithm, byte[] data)
            throws InterruptedException, KeyChainException, InvalidKeyException,
            NoSuchAlgorithmException, IllegalArgumentException, StringAliasNotFoundException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            return cryptOracleService.mac(alias, algorithm, data);
        } catch (RemoteException e) {
            extractRemoteSecretKeyException(e);
            extractRemoteSignException(e);
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * generate a key pair under the application control (eg. for use with DH)
     * 
     * @param ctx
     * @param alias the alias used for identifying the key
     * @param keyAlgorithm the key algorithm
     * @param keysize
     * @return encoded public key
     * @throws KeyChainException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InterruptedException
     */
    public static PublicKey generateKeyPair(Context ctx, String alias, String keyAlgorithm,
            int keysize) throws KeyChainException, InvalidKeySpecException,
            NoSuchAlgorithmException, InterruptedException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            byte[] encodedKey = cryptOracleService.generateKeyPair(alias, keyAlgorithm, keysize);

            return KeyFactory.getInstance(keyAlgorithm).generatePublic(
                    new X509EncodedKeySpec(encodedKey));
        } catch (RemoteException e) {
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * @param ctx
     * @param alias the alias used for identifying the key
     * @param agreementAlgorithm the agreement algorithm
     * @param key the public key
     * @param lastPhase whether this is the last step in the key agreement
     *            protocol
     * @return encoded intermediate public key
     * @throws KeyChainException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InterruptedException
     */
    public static PublicKey keyAgreementPhase(Context ctx, String alias, String keyAlgorithm,
            String agreementAlgorithm, PublicKey key, boolean lastPhase) throws KeyChainException,
            InvalidKeySpecException, NoSuchAlgorithmException, InterruptedException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();

            byte[] encodedKey = cryptOracleService.keyAgreementPhase(alias, keyAlgorithm,
                    agreementAlgorithm, key.getEncoded(), lastPhase);

            if (encodedKey == null)
                return null;

            return KeyFactory.getInstance("X509", bcX509Provider)
                    .generatePublic(new X509EncodedKeySpec(encodedKey));
        } catch (RemoteException e) {
            throw new KeyChainException(e);
        } catch (RuntimeException e) {
            throw new KeyChainException(e);
        } finally {
            cryptOracleConnection.close();
        }
    }

    /**
     * @hide
     */
    public static final Provider bcX509Provider = new BCX509Provider();
    public static final String EXTRA_SYMKEY = "symkey";

    private static final class BCX509Provider extends Provider {
        private static final long serialVersionUID = -4762217168644088168L;

        private BCX509Provider() {
            super("BCX509", 1, "custom BC provider providing X509 KeyFactory");

            addService(
                    "KeyFactory", "X509",
                    com.android.org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory.class
                            .getCanonicalName());
        }

        private void addService(String type, String algo, String className) {
            setProperty(type + "." + algo, className);
            putService(new Provider.Service(this, type, algo, className, null,
                    null));
        }
    }
}
