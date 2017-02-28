package com.unhandledexpression.wireguard.app;

import android.content.Intent;
import android.net.VpnService;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.southernstorm.noise.protocol.HandshakeState;
import com.unhandledexpression.wireguard.R;
import com.unhandledexpression.wireguard.VPN;
import com.unhandledexpression.wireguard.protocol.Configuration;
import com.unhandledexpression.wireguard.protocol.Hardcoded;
import com.unhandledexpression.wireguard.protocol.State;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final TextView txt = (TextView) findViewById(R.id.txt);

        if(true) {
            State.basicTest();
            State.preSharedKeyTest();

            /*
            (new AsyncTask<Void, Void, Void>() {
                @Override
                protected Void doInBackground(Void[] objects) {
                    State.test();

                    Configuration config = new Configuration(Hardcoded.myPrivateKey, Hardcoded.myIp,
                            Hardcoded.myIpPrefix, Hardcoded.route, Hardcoded.routePrefix,
                            null, 0,
                            Hardcoded.theirPublicKey, Hardcoded.serverName, Hardcoded.serverPort,
                            null);
                    final State state = new State(config, HandshakeState.INITIATOR);

                    Log.d("wg", "state: " + state.toString());


                    DatagramChannel channel = null;
                    try {
                        channel = DatagramChannel.open();
                        channel.connect(new InetSocketAddress(
                                InetAddress.getByName(Hardcoded.serverName), Hardcoded.serverPort));
                        byte[] initiatorPacket = state.createInitiatorPacket();
                        channel.write(ByteBuffer.wrap(initiatorPacket));

                        ByteBuffer responsePacket = ByteBuffer.allocate(32767);
                        SocketAddress addr = channel.receive(responsePacket);
                        Log.d("wg", "received packet from "+addr);
                        Log.d("wg", "response buffer before flip: "+responsePacket.position());
                        responsePacket.flip();
                        Log.d("wg", "response buffer after flip: position="+responsePacket.position());
                        Log.d("wg", "response buffer after flip: limit()="+responsePacket.limit());
                        state.receive(responsePacket, responsePacket.limit());

                        Log.d("wg", "sending keep alive");
                        //keep alive
                        byte[] keepAlivePacket = state.send(new byte[0], 0, 0);
                        int written = channel.write(ByteBuffer.wrap(keepAlivePacket));
                        if(written != keepAlivePacket.length) {
                            Log.d("wg", "error writing packet");
                        }

                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                txt.setText(state.toString());
                            }
                        });
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (ShortBufferException e) {
                        e.printStackTrace();
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    }

                    return null;
                }
            }).execute();
            */
        } else {
            createVPN();
        }
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
