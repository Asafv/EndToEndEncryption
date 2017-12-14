package com.example.asafv.endtoendsample;


import android.security.KeyPairGeneratorSpec;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import com.scottyab.aescrypt.AESCrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import io.reactivex.Single;

/**
 * Created by asafvaron on 09/10/2017.
 */
public class Crypto {

    private static final String TAG = "Crypto";

    private static final String KEY_ALIAS = "EndToEndSampleKeyAlias";

    private static Crypto sInstance = null;

    private KeyStore mKeystore;
    private byte[] secretEncryptedBytes;

    public static Crypto getInstance() {
        if (sInstance == null) {
            sInstance = new Crypto();
        }
        return sInstance;
    }

    /**
     * This will create a new keystore on the device if doesn't exist already with the KEY_ALIAS
     */
    private Crypto() {
        try {
            mKeystore = KeyStore.getInstance("AndroidKeyStore");
            mKeystore.load(null);
            createKeys();
        } catch (Exception e) {
            Log.e(TAG, "Crypto: unable to load KeyStore, ERR: ", e);
        }
    }

    // use for local testing
    public void test(String message) {
        // first encrypt the message
        String encryptedMessage = encryptMessageBody(message, getPublicKey());

        // sign the message with RSA
        byte[] signature = rsaSignatureSign(encryptedMessage);

        // verify and decrypt message body
        verifyAndDecryptMessageBody(encryptedMessage, getSecretEncryptedBytes(), signature, (RSAPublicKey) getPublicKey());
    }

    private void createKeys() {
        try {
            // Create new key if needed
            if (!mKeystore.containsAlias(KEY_ALIAS)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1); // TODO make sure to register when ever a new key is required

                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");

                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(EndToEndApp.getInstance().getApplicationContext())
                        .setAlias(KEY_ALIAS)
                        .setSubject(new X500Principal("CN=EndToEndSampleApp, O=Sheker"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();

                // init specs
                generator.initialize(spec);

                // generate the keys
                generator.generateKeyPair();
            } else {
                Log.w(TAG, "createKeys: KEY_ALIAS already exists :)");
            }
            refreshKeys();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    /**
     * Encrypts the message body and retrieves the encrypted String
     *
     * @param messageBody
     * @return encrypted message String
     */
    public String encryptMessageBody(@NonNull String messageBody, Key remotePublicKey) {
        try {
            // generate a secret key for each message
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secret = keyGen.generateKey();

            byte[] secretBytes = secret.getEncoded();

            // encrypt secret with RSA remote public (send this to server as well)
            secretEncryptedBytes = encryptWithRSA(secretBytes, remotePublicKey);

            // encrypt message with AES
            String encryptedMsg = AESCrypt.encrypt(new String(secretBytes), messageBody);

            /* Logs */
            if (BuildConfig.DEBUG) {
                Log.d(TAG, "encrypt secret with RSA remote public: " + Arrays.toString(secretEncryptedBytes));
                Log.e(TAG, "encryptString: " + encryptedMsg);
            }

            return encryptedMsg;

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String verifyAndDecryptMessageBody(String encryptedMessage, byte[] secretEncryptedBytes,
                                              byte[] realSignatureBytes, RSAPublicKey remotePublicKey) {
        // verify rsa signature
        if (rsaSignatureVerify(encryptedMessage.getBytes(), realSignatureBytes, remotePublicKey)) {

            // first decode the secret key from the rsa message
            byte[] clearSecret = decryptWithRSA(secretEncryptedBytes, getPrivateKey());

            if (clearSecret != null) {
                String clearText = null;
                try {
                    clearText = AESCrypt.decrypt(new String(clearSecret), encryptedMessage);
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                }

                /* Logs */
                if (BuildConfig.DEBUG) {
                    Log.i(TAG, "Digital Signature Verified");
                    Log.d(TAG, "clearSecret: " + Arrays.toString(clearSecret));
                    Log.i(TAG, "clearText: " + clearText);
                }

                return clearText;
            } else {
                Log.e(TAG, "verifyAndDecryptMessageBody: ERR: cannot decrypt without secretOriginal");
            }
        } else {
            Log.e(TAG, "verifyAndDecryptMessageBody, DigitalSignature is not verified!");
        }
        return null;
    }

    private boolean rsaSignatureVerify(byte[] encMessageBytes, byte[] realSignature, PublicKey publicKey) {
        try {
            Signature dsaRemote = Signature.getInstance("SHA256withRSA");
            dsaRemote.initVerify(publicKey);

            dsaRemote.update(encMessageBytes);

            // returns true if success verify
            return dsaRemote.verify(realSignature);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public byte[] rsaSignatureSign(String encrypted_msg) {
        try {
            Signature dsa = Signature.getInstance("SHA256withRSA");
            // sign with private key
            dsa.initSign(getPrivateKey());

            // write bytes into signature
            dsa.update(encrypted_msg.getBytes());

            // sign it
            byte[] signature = dsa.sign();

            if (BuildConfig.DEBUG) {
                Log.d(TAG, "rsaSignatureSign(Base64): "
                        + Base64.encodeToString(signature, Base64.NO_WRAP));
            }

            return signature;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] encryptWithRSA(byte[] secretBytes, Key remotePublicKey) {
        try {
            // Bouncy Castle security provider
            Provider p = Security.getProvider("BC");
            Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", p);

            inCipher.init(Cipher.ENCRYPT_MODE, remotePublicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);

            cipherOutputStream.write(secretBytes);
            cipherOutputStream.close();

            return outputStream.toByteArray();

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] decryptWithRSA(byte[] secretEncrypted, Key key_for_dec) {
        try {
            // decrypt does not need a Provider
            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            output.init(Cipher.DECRYPT_MODE, key_for_dec);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(secretEncrypted), output);
            ArrayList<Byte> values = new ArrayList<>();

            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            return bytes;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void refreshKeys() {
        ArrayList<String> keyAliases = new ArrayList<>();
        try {
            Enumeration<String> aliases = mKeystore.aliases();
            while (aliases.hasMoreElements()) {
                keyAliases.add(aliases.nextElement());
            }
            Log.d(TAG, "refreshKeys: " + keyAliases);
        } catch (Exception e) {
            Log.e(TAG, "refreshKeys: ERR: ", e);
        }
    }

    public void deleteKey() {
        try {
            mKeystore.deleteEntry(KEY_ALIAS);
            Log.w(TAG, "deleteKey: deleted");
            refreshKeys();
        } catch (KeyStoreException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    // use to send the secret to server
    public byte[] getSecretEncryptedBytes() {
        return secretEncryptedBytes;
    }

    private PrivateKey getPrivateKey() {
        // current users private/public keys
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeystore.getEntry(KEY_ALIAS, null);
            return privateKeyEntry.getPrivateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;

    }

    public PublicKey getPublicKey() {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeystore.getEntry(KEY_ALIAS, null);
            return privateKeyEntry.getCertificate().getPublicKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Key generatePublicKeyFromEncoded64Key(String encodedBase64RsaKey) {
        try {
            // decode base64 rsa public into bytes
            byte[] decodedBytes = Base64.decode(encodedBase64RsaKey, Base64.NO_WRAP);

            // generate a new RSA public key to verify it is correctly assigned with
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(decodedBytes));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Single<String> encryptMessageBodyObs(String clearMessage, PublicKey publicKey) {
        return Single.create(e -> {
            try {
                // generate a secret key for each message
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey secret = keyGen.generateKey();

                byte[] secretBytes = secret.getEncoded();

                // encrypt secret with RSA remote public (send this to server as well)
                secretEncryptedBytes = encryptWithRSA(secretBytes, publicKey);

                // encrypt message with AES
                String encryptedMsg = AESCrypt.encrypt(new String(secretBytes), clearMessage);

            /* Logs */
                if (BuildConfig.DEBUG) {
                    Log.d(TAG, "encrypt secret with RSA remote public: " + Arrays.toString(secretEncryptedBytes));
                    Log.e(TAG, "encryptString: " + encryptedMsg);
                }

                e.onSuccess(encryptedMsg);

            } catch (GeneralSecurityException gse) {
                e.onError(gse);
            }
        });
    }

    public Single<String> verifyAndDecryptMessageBodyObs(String encryptedMessage, byte[] secretEncryptedBytes,
                                                         byte[] realSignatureBytes, RSAPublicKey remotePublicKey) {
        return Single.create(e -> {
            // verify rsa signature
            if (rsaSignatureVerify(encryptedMessage.getBytes(), realSignatureBytes, remotePublicKey)) {

                // first decode the secret key from the rsa message
                byte[] clearSecret = decryptWithRSA(secretEncryptedBytes, getPrivateKey());

                if (clearSecret != null) {
                    String clearText = null;
                    try {
                        clearText = AESCrypt.decrypt(new String(clearSecret), encryptedMessage);
                    } catch (GeneralSecurityException gse) {
                        gse.printStackTrace();
                        e.onError(gse);
                    }

                    if (BuildConfig.DEBUG) {
                        Log.i(TAG, "Digital Signature Verified");
                        Log.d(TAG, "clearSecret: " + Arrays.toString(clearSecret));
                        Log.i(TAG, "clearText: " + clearText);
                    }

                    e.onSuccess(clearText);
                } else {
                    Log.e(TAG, "verifyAndDecryptMessageBody: ERR: cannot decrypt without secretOriginal");
                    e.onError(new Throwable("verifyAndDecryptMessageBody: ERR: cannot decrypt without secretOriginal"));
                }
            } else {
                Log.e(TAG, "DigitalSignature is not verified!");
                e.onError(new Throwable("DigitalSignature is not verified!"));
            }
        });
    }
}