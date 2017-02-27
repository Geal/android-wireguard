package com.unhandledexpression.wireguard.protocol;

import com.southernstorm.noise.crypto.Blake2sMessageDigest;
import com.southernstorm.noise.protocol.ChaChaPolyCipherState;
import com.southernstorm.noise.protocol.CipherStatePair;
import com.southernstorm.noise.protocol.HandshakeState;
import com.unhandledexpression.wireguard.Utils;

import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

import static java.lang.Math.min;


/**
 * Created by geal on 25/02/2017.
 */

public class State {
    public static final String PROLOGUE          = "WireGuard v0 zx2c4 Jason@zx2c4.com";
    public static final byte[] initiatorHeader   = { 1, 0, 0, 0 };
    public static final byte[] responseHeader    = { 2, 0, 0, 0 };
    public static final byte[] cookieReplyHeader = { 3, 0, 0, 0 };
    public static final byte[] transportHeader   = { 4, 0, 0, 0 };

    public              Configuration       configuration;
    public              HandshakeState      handshakeState;
    public              int                 myIndex;
    public              int                 remoteMyInitiatorIndex;
    public              long                sendCounter = 0;
    public              long                receiveCounter = 0;
    public              int                 responderIndex;
    public              int                 initiatorIndex;
    public              DatagramChannel     channel;
    public              CipherStatePair     handshakePair;

    public State(Configuration _configuration) {
        configuration = _configuration;

        byte[] data = Base64.decode(configuration.myPrivateKey, Base64.DEFAULT);
        byte[] pubData = Base64.decode(configuration.theirPublicKey, Base64.DEFAULT);
        Log.d("wg", "server pubkey("+pubData.length+" bytes): "+Utils.hexdump(pubData));

        Random rand = new SecureRandom();
        myIndex = rand.nextInt();

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

        packet.putInt(myIndex);

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
                bb.order(ByteOrder.LITTLE_ENDIAN);
                responderIndex = bb.getInt();
                initiatorIndex = bb.getInt();

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
            Log.d("wg", "initiator state before send: "+handshakeState.getAction());
            byte[] bytePacket = createInitiatorPacket();
            channel = DatagramChannel.open();
            channel.connect(new InetSocketAddress(InetAddress.getByName(Hardcoded.serverName), Hardcoded.serverPort));
            //DatagramPacket udpPacket = new DatagramPacket(bytePacket, bytePacket.length, channel.getRemoteAddress());

            //channel.send(udpPacket);
            channel.write(ByteBuffer.wrap(bytePacket, 0, bytePacket.length));
            Log.i("wg", "sent packet");
            Log.d("wg", "initiator state after send: "+handshakeState.getAction());



            //byte[] receivedData = new byte[92];
            //DatagramPacket received = new DatagramPacket(receivedData, receivedData.length);
            //channel.receive(received);
            ByteBuffer bb = ByteBuffer.allocate(92);
            int bytesRead = channel.read(bb);

            Log.i("wg", "received("+bytesRead+" bytes): ");
            Log.d("wg", Utils.formatHexDump(bb.array(), 0, bytesRead));
            if(consumeResponsePacket(Arrays.copyOfRange(bb.array(), 0, bytesRead))) {
                Log.i("wg", "the response packet was correct");
            }
            Log.d("wg", "initiator state after receive: "+handshakeState.getAction());

            handshakePair = handshakeState.split();
            Log.d("wg", "initiator state after split: "+handshakeState.getAction());

            Log.d("wg", "sending keep alive");
            //keep alive
            send(new byte[0], 0);
            Log.d("wg", "sent keep alive");

            /*
            Log.d("wg", "sent, waiting for answer");

            try {
                byte[] keepAlive = receive();
                Log.d("wg", "received: "+Utils.hexdump(keepAlive));

            } catch (BadPaddingException e) {
                e.printStackTrace();
            }

            */

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

    public void send(byte[] data, int length) throws IOException {
        int index = 0;
        ChaChaPolyCipherState sender = (ChaChaPolyCipherState) handshakePair.getSender();
        while(index <= length) {
            //int bufferSize = length + 32;
            int bufferSize = 512;
            //480 = 512 - header 16 bytes - mac 16 bytes
            int maxPayloadSize = bufferSize - 16 - 16;

            ByteBuffer bb = ByteBuffer.allocate(bufferSize);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.put(transportHeader);
            bb.putInt(responderIndex);

            bb.putLong(sender.n);

            byte[] packet = bb.array();
            Log.i("wg", "header with counter: "+Utils.hexdump(Arrays.copyOfRange(packet, 0, 16)));
             int toCopy = min(maxPayloadSize, data.length - index);
            Log.i("wg", "to copy: "+toCopy);
            try {
                int copied = sender.encryptWithAd(null, data, index, packet, 16, toCopy);
                index += copied;

                Log.i("wg", "will send ("+(copied+16)+" bytes): "+Utils.hexdump(Arrays.copyOfRange(packet, 0, copied+16)));
                //Log.i("wg", "complete:  "+Utils.hexdump(packet));


                channel.write(ByteBuffer.wrap(packet, 0, copied+16));
                Log.i("wg", "sent packet: "+sender.n+" -> "+(copied+16)+" bytes");
            } catch (ShortBufferException e) {
                e.printStackTrace();
            }

        }
    }

    public byte[] receive() throws IOException, ShortBufferException, BadPaddingException {

        ByteBuffer bb = ByteBuffer.allocate(32767);
        int bytesRead = channel.read(bb);

        Log.i("wg", "received("+bytesRead+" bytes): ");
        Log.d("wg", Utils.formatHexDump(bb.array(), 0, bytesRead));

        byte[] receivedData = Arrays.copyOfRange(bb.array(), 0, bytesRead);
        Log.i("wg", "received: "+Utils.hexdump(receivedData));


        if(     receivedData[0] == transportHeader[0] &&
                receivedData[1] == transportHeader[1] &&
                receivedData[2] == transportHeader[2] &&
                receivedData[3] == transportHeader[3]) {

            ByteBuffer bb2 = ByteBuffer.wrap(Arrays.copyOfRange(receivedData, 4, 16));

            bb2.order(ByteOrder.LITTLE_ENDIAN);
            int remoteIndex = bb2.getInt();
            receiveCounter  = bb2.getLong();
            Log.d("wg", "got remote index: "+remoteIndex);
            Log.d("wg", "got receive counter: "+receiveCounter);
            ChaChaPolyCipherState receiver = (ChaChaPolyCipherState) handshakePair.getReceiver();
                    Log.d("wg", "handshake pair receiver counter: "+ receiver.n);

            byte[] payload = new byte[receivedData.length - 32];
            int decrypted = handshakePair.getReceiver().decryptWithAd(null, receivedData, 16,
                    payload, 0, receivedData.length - 16);

            Log.i("wg", "decrypted packet("+decrypted+" bytes of payload) with counter: "+receiveCounter);
            return payload;

            //FIXME: check the packet's length

        } else {
            Log.d("wg", "invalid transport header packet");
            return null;
        }

    }
}
