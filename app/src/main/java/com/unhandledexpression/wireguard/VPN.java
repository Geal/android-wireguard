package com.unhandledexpression.wireguard;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.unhandledexpression.wireguard.protocol.Hardcoded;
import com.unhandledexpression.wireguard.protocol.State;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import static android.app.Activity.RESULT_OK;

/**
 * Created by geal on 25/02/2017.
 */

public class VPN extends VpnService {
    public VPN() {

    }

    private Thread mThread;
    private ParcelFileDescriptor mInterface;
    //a. Configure a builder for the interface.
    Builder builder = new Builder();

    // Services interface
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Start a new session by creating a new thread.
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Log.d("wg", "starting VPN");

                    //a. Configure the TUN and get the interface.
                    mInterface = builder.setSession("MyVPNService")
                            .addAddress(Hardcoded.myIp, Hardcoded.myIpPrefix)
                            .addDnsServer("8.8.8.8")
                            .addRoute(Hardcoded.route, Hardcoded.routePrefix).establish();
                    //b. Packets to be sent are queued in this input stream.
                    FileInputStream in = new FileInputStream(
                            mInterface.getFileDescriptor());
                    //b. Packets received need to be written to this output stream.
                    FileOutputStream out = new FileOutputStream(
                            mInterface.getFileDescriptor());


                    final State state = new State(Hardcoded.myPrivateKey, Hardcoded.serverPublicKey);

                    Log.d("wg", "state: "+state.toString());

                    state.initiate();
                    protect(state.socket);
                    /*
                    //c. The UDP channel can be used to pass/get ip package to/from server
                    DatagramChannel tunnel = DatagramChannel.open();
                    // Connect to the server, localhost is used for demonstration only.
                    tunnel.connect(new InetSocketAddress("127.0.0.1", 8087));
                    //d. Protect this socket, so package send by it will not be feedback to the vpn service.
                    protect(tunnel.socket());
                    //e. Use a loop to pass packets.
*/
                    ByteBuffer packet = ByteBuffer.allocate(32767);

                    Log.d("wg", "starting loop");
                    while (true) {
                        boolean idle = true;
                        // Read the outgoing packet from the input stream.
                        int length = in.read(packet.array());

                        if (length > 0) {
                            Log.d("wg", "SEND "+length+" bytes");
                            // Write the outgoing packet to the tunnel.
                            packet.limit(length);
                            state.send(packet.array(), length);
                            packet.clear();
                            // There might be more outgoing packets.
                            idle = false;
                        } else {
                            Thread.sleep(100);

                            continue;
                        }
                        Log.d("wg", "RECEIVE");

                        //while(true) {
                            byte[] received = state.receive();
                            out.write(received, 0, received.length);
                            Log.d("wg", "RECEIVED "+received.length+" bytes");
                            Thread.sleep(100);

                        //}

                        /*// Read the incoming packet from the tunnel.
                        length = state.receive(packet);
                        if (length > 0) {
                            // Ignore control messages, which start with zero.
                            if (packet.get(0) != 0) {
                                // Write the incoming packet to the output stream.
                                out.write(packet.array(), 0, length);
                            }
                            packet.clear();
                            // There might be more incoming packets.
                            idle = false;
                            // If we were sending, switch to receiving.
                            if (timer > 0) {
                                timer = 0;
                            }
                        }*/
                        //Thread.sleep(100);
                    }

                } catch (Exception e) {
                    // Catch any exception
                    e.printStackTrace();
                } finally {
                    try {
                        if (mInterface != null) {
                            mInterface.close();
                            mInterface = null;
                        }
                    } catch (Exception e) {

                    }
                }
            }

        }, "MyVpnRunnable");

        //start the service
        mThread.start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (mThread != null) {
            mThread.interrupt();
        }
        super.onDestroy();
    }
}
