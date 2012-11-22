
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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.crypto.Cipher;

/**
 * @author Kjell Braden <kjell.braden@stud.tu-darmstadt.de>
 */
public final class CryptOracle {

    private static class AliasResponse extends IKeyChainAliasCallback.Stub {
        private final KeyChainAliasCallback keyChainAliasResponse;

        private AliasResponse(KeyChainAliasCallback keyChainAliasResponse) {
            this.keyChainAliasResponse = keyChainAliasResponse;
        }

        @Override
        public void alias(String alias) {
            this.keyChainAliasResponse.alias(alias);
        }
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

    private static final String ACTION_GENERATE = "com.android.keychain.GENERATE";

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
     * @param ctx
     * @param alias identifier of the key to be used for decryption
     * @param padding mode and padding specification, as described in
     *            {@link Cipher}
     * @param encryptedData the data to be decrypted
     * @return decrypted data
     * @throws InterruptedException
     * @throws KeyChainException
     */
    public static byte[] decryptData(Context ctx, String alias, String padding,
            byte[] encryptedData) throws KeyChainException, InterruptedException {
        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            return cryptOracleService.decryptData(alias, padding, encryptedData);
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
     * @param alias identifier of the key to be used for decryption
     * @param padding mode and padding specification, as described in
     *            {@link Cipher}
     * @param data the data to be encrypted
     * @return encrypted data
     * @throws KeyChainException
     * @throws InterruptedException
     */
    public static byte[] encryptData(Context ctx, String alias, String padding, byte[] data)
            throws KeyChainException, InterruptedException {

        CryptOracleConnection cryptOracleConnection = bind(ctx);
        try {
            ICryptOracleService cryptOracleService = cryptOracleConnection.getService();
            return cryptOracleService.encryptData(alias, padding, data);
        } catch (RemoteException e) {
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

    /**
     * Shows a dialog for key generation parameters. If the user confirms, a
     * private key, public key and an appropriate certificate will be generated
     * and stored in the KeyStore. Their alias will be supplied in the response
     * callback. <br/>
     * The public key can be retrieved using
     * {@link KeyChain#getCertificateChain(Context, String)}
     * 
     * @param activity The {@link Activity} context to use for launching the new
     *            sub-Activity to prompt the user to select a private key; used
     *            only to call startActivity(); must not be null.
     * @param response Callback to invoke when the request completes; must not
     *            be null
     * @see KeyChain#getCertificateChain(Context, String)
     */
    public static void generate(Activity activity, KeyChainAliasCallback response) {
        if (activity == null)
            throw new NullPointerException("activity == null");
        if (response == null)
            throw new NullPointerException("response == null");
        Intent intent = new Intent(ACTION_GENERATE);
        intent.putExtra(KeyChain.EXTRA_RESPONSE, new AliasResponse(response));
        // the PendingIntent is used to get calling package name
        intent.putExtra(KeyChain.EXTRA_SENDER,
                PendingIntent.getActivity(activity, 0, new Intent(), 0));
        activity.startActivity(intent);
    }
}
