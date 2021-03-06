package com.example.asafv.endtoendsample;

import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.security.interfaces.RSAPublicKey;

import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.schedulers.Schedulers;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    private Crypto mCrypto;

    // encrypt
    private EditText etMessage;
    private Button btnEncrypt;
    private TextView tvEncryptedMessage;

    // decrypt
    private RelativeLayout rlDecryptContainer;
    private Button btnDecrypt;
    private TextView tvDecryptedMessage;

    private Button btnReset;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mCrypto = Crypto.getInstance();

        // init views
        findViews();
        init();
    }

    private void findViews() {
        etMessage = findViewById(R.id.etMessage);
        btnEncrypt = findViewById(R.id.btnEncrypt);
        tvEncryptedMessage = findViewById(R.id.tvEncryptedMessage);

        rlDecryptContainer = findViewById(R.id.rlDecryptContainer);
        btnDecrypt = findViewById(R.id.btnDecrypt);
        tvDecryptedMessage = findViewById(R.id.tvDecryptedMessage);

        btnReset = findViewById(R.id.btnReset);
    }

    private void init() {
        btnEncrypt.setOnClickListener(v -> {
            String clearMessage = etMessage.getText().toString().trim();
            if (clearMessage.isEmpty()) {
                Toast.makeText(this, "Nothing to encrypt", Toast.LENGTH_SHORT).show();
            } else {

                // with observables (Single)
                // encrypt message with (remote) public key
                mCrypto.encryptMessageBodyObs(clearMessage, mCrypto.getPublicKey())
                        .observeOn(AndroidSchedulers.mainThread())
                        .subscribeOn(Schedulers.io())
                        .subscribe(
                                s -> {
                                    Log.i(TAG, "encryptMessageBodyObs: onSuccess");
                                    if (!s.isEmpty()) {
                                        tvEncryptedMessage.setText(s);
                                        setupDecryptContainer();
                                    }
                                }, throwable -> {
                                    Log.e(TAG, "encryptMessageBodyObs: onError: ", throwable);
                                    Toast.makeText(this, throwable.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
                                }
                        );

/*
                // normal way to encrypt - should run on background thread
                String encryptedMessage = mCrypto.encryptMessageBody(clearMessage, mCrypto.getPublicKey());
                if (encryptedMessage != null) {
                    tvEncryptedMessage.setText(encryptedMessage);
                    setupDecryptContainer();
                } else {
                    Toast.makeText(this, "Error encrypting\nPlease check the log.", Toast.LENGTH_SHORT).show();
                }
*/
            }
        });

        btnReset.setOnClickListener(v -> resetAll());
    }

    private void setupDecryptContainer() {
        // hide keyboard
        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        assert imm != null;
        imm.hideSoftInputFromWindow(rlDecryptContainer.getWindowToken(), 0);

        rlDecryptContainer.setVisibility(View.VISIBLE);
        btnDecrypt.setOnClickListener(v -> {
            String encryptedMessage = tvEncryptedMessage.getText().toString();

            if (!encryptedMessage.isEmpty()) {
                // with observables (Single)
                mCrypto.verifyAndDecryptMessageBodyObs(encryptedMessage,
                        mCrypto.getSecretEncryptedBytes(),
                        mCrypto.rsaSignatureSign(encryptedMessage),
                        (RSAPublicKey) mCrypto.getPublicKey())
                        .observeOn(AndroidSchedulers.mainThread())
                        .subscribeOn(Schedulers.io())
                        .subscribe(
                                s -> {
                                    Log.i(TAG, "verifyAndDecryptMessageBodyObs: onSuccess");
                                    if (!s.isEmpty()) {
                                        tvDecryptedMessage.setText(s);
                                    }
                                },
                                throwable -> {
                                    Log.e(TAG, "verifyAndDecryptMessageBodyObs: onError: ", throwable);
                                    Toast.makeText(this, throwable.getLocalizedMessage(),
                                            Toast.LENGTH_SHORT).show();
                                }
                        );

/*
                // normal way - should be done on background thread
                // verify the message was signed with the following params
                // 1. secret bytes
                // 2. rsa signature sign
                // 3. remote RSA public key (currently using local for example)
                String clearMessage = mCrypto.verifyAndDecryptMessageBody(encryptedMessage,
                        mCrypto.getSecretEncryptedBytes(),
                        mCrypto.rsaSignatureSign(encryptedMessage),
                        (RSAPublicKey) mCrypto.getPublicKey());

                if (clearMessage != null) {
                    tvDecryptedMessage.setText(clearMessage);
                }
*/
            }
        });
    }

    private void resetAll() {
        etMessage.setText("");
        tvEncryptedMessage.setText("");
        tvDecryptedMessage.setText("");
        rlDecryptContainer.setVisibility(View.GONE);
    }
}
