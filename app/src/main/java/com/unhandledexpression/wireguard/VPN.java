package com.unhandledexpression.wireguard;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.unhandledexpression.wireguard.protocol.Hardcoded;
import com.unhandledexpression.wireguard.protocol.State;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;

/**
 * Created by geal on 25/02/2017.
 */

public class VPN extends VpnService {
    private static final int TIMEOUT = 3000; // Wait timeout (milliseconds)

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
                    protect(state.channel.socket());
                    state.channel.configureBlocking(false);


                    Selector selector = Selector.open();
                    state.channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);


                    Log.d("wg", "starting loop");
                    while (true) {
                        if (selector.select(TIMEOUT) == 0) {
                            //Log.d("wg", "TIMEOUT");
                            continue;
                        }

                        // Get iterator on set of keys with I/O to process
                        Iterator<SelectionKey> keyIter = selector.selectedKeys().iterator();
                        while (keyIter.hasNext()) {
                            SelectionKey key = keyIter.next(); // Key is bit mask

                            // Client socket channel has pending data?
                            if (key.isValid() && key.isReadable()) {
                                Log.d("wg", "RECEIVE");

                                //while(true) {
                                byte[] received = state.receive();
                                if (received == null) {
                                    Log.d("wg", "received an empty array");
                                    continue;
                                }
                                Log.d("wg", "hexdump:\n"+Utils.formatHexDump(received, 0, received.length));

                                out.write(received, 0, received.length);
                                Log.d("wg", "RECEIVED "+received.length+" bytes");
                                Thread.sleep(100);
                            }

                            // Client socket channel is available for writing and
                            // key is valid (i.e., channel not closed).
                            if (key.isValid() && key.isWritable()) {
                                ByteBuffer packet = ByteBuffer.allocate(32767);

                                int length = in.read(packet.array());

                                if (length > 0) {
                                    Log.d("wg", "SEND "+length+" bytes");
                                    Log.d("wg", "hexdump:\n"+Utils.formatHexDump(packet.array(), 0, length));
                                    //packet.limit(length);
                                    state.send(packet.array(), length);
                                    packet.clear();

                                }
                            }

                            keyIter.remove();
                        }
                        /*
                        // Read the outgoing packet from the input stream.
                        int length = in.read(packet.array());

                        if (length > 0) {
                            Log.d("wg", "SEND "+length+" bytes");
                            Log.d("wg", "hexdump:\n"+Utils.formatHexDump(packet.array(), 0, length));
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
                        Log.d("wg", "hexdump:\n"+Utils.formatHexDump(received, 0, received.length));

                        out.write(received, 0, received.length);
                            Log.d("wg", "RECEIVED "+received.length+" bytes");
                            Thread.sleep(100);

                        //}
                        */


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