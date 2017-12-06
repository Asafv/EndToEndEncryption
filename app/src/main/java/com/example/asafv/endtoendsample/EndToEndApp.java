package com.example.asafv.endtoendsample;

import android.app.Application;

/**
 * Created by AsafV on 06/12/2017.
 */

public class EndToEndApp extends Application {

    private static EndToEndApp mInstance;

    public static synchronized EndToEndApp getInstance() {
        return mInstance;
    }


    @Override
    public void onCreate() {
        super.onCreate();

        // Normal app init code...
        mInstance = this;

        // init crypto for keystore generation
        Crypto.getInstance();
    }
}
