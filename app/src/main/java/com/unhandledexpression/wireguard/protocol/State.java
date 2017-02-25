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
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.ShortBufferException;

/**
 * Created by geal on 25/02/2017.
 */

public class State {
    public static String PROLOGUE = "WireGuard v0 zx2c4 Jason@zx2c4.com";
    public byte[]            preSharedKey;
    public HandshakeState    handshakeState;

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
        byte[] header = new byte[4];
        header[0] = 1;
        header[1] = 0;
        header[2] = 0;
        header[3] = 0;
        packet.put(header);

        packet.putInt(Hardcoded.mySenderIndex);

        byte[] payload = new byte[108];
        handshakeState.writeMessage(payload, 0, tai, 0, tai.length);
        packet.put(payload);

        Log.i("wg", "payload: "+ Utils.hexdump(payload));

        Log.i("wg", "packet so far: "+ Utils.hexdump(Arrays.copyOfRange(packet.array(), 0, 116)));


        byte[] serverKey = new byte[32];
        handshakeState.getRemotePublicKey().getPublicKey(serverKey, 0);
        Log.d("wg", "initiator pubkey("+serverKey.length+" bytes): "+Utils.hexdump(serverKey));

        Blake2sMessageDigest digest = new Blake2sMessageDigest();
        digest.update(serverKey);
        digest.update(packet.array(), 0, 116);

        byte[] mac1 = digest.digest();
        packet.put(mac1, 0, 16);
        Log.i("wg", "complete mac1: "+ Utils.hexdump(mac1));
        Log.i("wg", "reduced mac1: "+ Utils.hexdump(Arrays.copyOfRange(mac1, 0, 16)));

        byte[] bytePacket = packet.array();

        Log.i("wg", "generated packet ("+bytePacket.length+" bytes): "+ Utils.hexdump(bytePacket));

        return bytePacket;
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