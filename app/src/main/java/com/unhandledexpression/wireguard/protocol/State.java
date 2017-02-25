package com.unhandledexpression.wireguard.protocol;

import com.southernstorm.noise.crypto.Blake2sMessageDigest;
import com.southernstorm.noise.protocol.HandshakeState;
import com.unhandledexpression.wireguard.Utils;

import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

/**
 * Created by geal on 25/02/2017.
 */

public class State {
    public static final String PROLOGUE          = "WireGuard v0 zx2c4 Jason@zx2c4.com";
    public static final byte[] initiatorHeader   = { 1, 0, 0, 0 };
    public static final byte[] responseHeader    = { 2, 0, 0, 0 };
    public static final byte[] cookieReplyHeader = { 3, 0, 0, 0 };
    public static final byte[] transportHeader   = { 4, 0, 0, 0 };

    public              byte[]              preSharedKey;
    public              HandshakeState      handshakeState;

    public State(String b64PrivateKey, String b64ServerPublicKey) {
        byte[] data = Base64.decode(b64PrivateKey, Base64.DEFAULT);
        byte[] pubData = Base64.decode(b64ServerPublicKey, Base64.DEFAULT);
        Log.d("wg", "server pubkey("+pubData.length+" bytes): "+Utils.hexdump(pubData));


        try {
            handshakeState = new HandshakeState("Noise_IK_25519_ChaChaPoly_BLAKE2s", HandshakeState.INITIATOR);
            handshakeState.setPrologue(PROLOGUE.getBytes(), 0, PROLOGUE.length());

            handshakeState.getLocalKeyPair().setPrivateKey(data, 0);
            handshakeState.getRemotePublicKey().setPublicKey(pubData,0);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public byte[] createInitiatorPacket() throws ShortBufferException {
        handshakeState.start();

        byte[] tai = Time.tai64n();
        ByteBuffer packet = ByteBuffer.allocate(148);
        packet.order(ByteOrder.LITTLE_ENDIAN);
        packet.put(initiatorHeader);

        packet.putInt(Hardcoded.mySenderIndex);

        byte[] payload = new byte[108];
        handshakeState.writeMessage(payload, 0, tai, 0, tai.length);
        packet.put(payload);

        Log.i("wg", "payload: "+ Utils.hexdump(payload));
        byte[] ephemeral = new byte[32];
        handshakeState.getLocalKeyPair().getPublicKey(ephemeral, 0);
        Log.i("wg", "ephemeral pubkey: "+Utils.hexdump(ephemeral));

        Log.i("wg", "packet so far: "+ Utils.hexdump(Arrays.copyOfRange(packet.array(), 0, 116)));


        byte[] serverKey = new byte[32];
        handshakeState.getRemotePublicKey().getPublicKey(serverKey, 0);

        try {
            Blake2sMessageDigest digest = new Blake2sMessageDigest(16, null);

            Log.d("wg", "hashing serverKey: "+Utils.hexdump(serverKey));
            digest.update(serverKey);
            Log.d("wg", "hashing packet: "+Utils.hexdump(Arrays.copyOfRange(packet.array(), 0, 116)));
            digest.update(packet.array(), 0, 116);

            byte[] mac1 = digest.digest();
            packet.put(mac1, 0, 16);
            Log.i("wg", "complete mac1: "+ Utils.hexdump(mac1));
            Log.i("wg", "reduced mac1: "+ Utils.hexdump(Arrays.copyOfRange(mac1, 0, 16)));
        } catch (DigestException e) {
            e.printStackTrace();
        }

        byte[] bytePacket = packet.array();

        Log.i("wg", "generated packet ("+bytePacket.length+" bytes): "+ Utils.hexdump(bytePacket));

        return bytePacket;
    }

    public boolean consumeResponsePacket(byte[] responsePacket) {
        if(     responsePacket[0] == responseHeader[0] &&
                responsePacket[1] == responseHeader[1] &&
                responsePacket[2] == responseHeader[2] &&
                responsePacket[3] == responseHeader[3]) {

            //FIXME: check the packet's length

            try {
                byte[] myPublicKey = new byte[32];
                handshakeState.getLocalKeyPair().getPublicKey(myPublicKey, 0);
                Blake2sMessageDigest digest = new Blake2sMessageDigest(16, null);

                //Log.d("wg", "hashing serverKey: "+Utils.hexdump(myPublicKey));
                digest.update(myPublicKey);
                //Log.d("wg", "hashing packet: "+Utils.hexdump(Arrays.copyOfRange(packet.array(), 0, 116)));
                digest.update(responsePacket, 0, 60);

                byte[] mac1 = Arrays.copyOfRange(responsePacket, 60, 76);
                if(!Arrays.equals(mac1, digest.digest())) {
                    Log.d("wg", "invalid mac1");
                    return false;
                }

                //FIXME: mac2 check deactivated for now
                if(false) {
                    byte[] mac2 = Arrays.copyOfRange(responsePacket, 76, 92);
                    //???
                }

                ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(responsePacket, 4, 12));
                int responderIndex = bb.getInt();
                int initiatorIndex = bb.getInt();

                Log.i("wg", "response has initiator="+initiatorIndex+" and responder="+responderIndex);

                byte[] payload = new byte[0]; //whatever size
                handshakeState.readMessage(responsePacket, 12, 48, payload, 0);

                return true;
            } catch (DigestException e) {
                e.printStackTrace();
            } catch (ShortBufferException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            }
            return false;
        } else {
            Log.d("wg", "invalid packet header");
            //FIXME: we might get the cookie reply here instead
            return false;
        }
    }

    public void initiate() {
        try {
            byte[] bytePacket = createInitiatorPacket();
            DatagramSocket s = new DatagramSocket();
            s.connect(InetAddress.getByName(Hardcoded.serverName), Hardcoded.serverPort);
            SocketAddress addr = s.getLocalSocketAddress();
            DatagramPacket udpPacket = new DatagramPacket(bytePacket, bytePacket.length, s.getRemoteSocketAddress());

            s.send(udpPacket);
            Log.i("wg", "sent packet");


            byte[] receivedData = new byte[92];
            DatagramPacket received = new DatagramPacket(receivedData, receivedData.length);
            s.receive(received);

            Log.i("wg", "received: "+Utils.hexdump(receivedData));
            if(consumeResponsePacket(receivedData)) {
                Log.i("wg", "the response packet was correct");
            }
        } catch (ShortBufferException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }
}
