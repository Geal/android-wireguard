package com.unhandledexpression.wireguard.app;

import android.content.Intent;
import android.net.VpnService;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.unhandledexpression.wireguard.R;
import com.unhandledexpression.wireguard.VPN;
import com.unhandledexpression.wireguard.protocol.Hardcoded;
import com.unhandledexpression.wireguard.protocol.State;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final TextView txt = (TextView) findViewById(R.id.txt);

        /*
        (new AsyncTask<Void, Void, Void>() {
            @Override
            protected Void doInBackground(Void[] objects) {
                final State state = new State(Hardcoded.myPrivateKey, Hardcoded.serverPublicKey);

                Log.d("wg", "state: "+state.toString());

                state.initiate();
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        txt.setText(state.toString());
                    }
                });
                return null;
            }
        }).execute();
*/
        createVPN();
    }

    void createVPN() {
        Intent intent = VpnService.prepare(getApplicationContext());
        if (intent != null) {
            startActivityForResult(intent, 0);
        } else {
            onActivityResult(0, RESULT_OK, null);
        }
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            Intent intent = new Intent(this, VPN.class);
            startService(intent);
        }
    }
}
