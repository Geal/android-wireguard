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
    public static final int    initiatorHeader   = 1;
    public static final int    responseHeader    = 2;
    public static final int    cookieReplyHeader = 3;
    public static final int    transportHeader   = 4;

    public static final int    HEADER_SIZE            = 4;
    public static final int    INDEX_SIZE             = 4;
    public static final int    MAC_SIZE               = 16;
    public static final int    PUBLIC_KEY_SIZE        = 32;
    // ephemeral(32) + static(32) + static mac(16) + timestamp(12) + timestamp mac(16)
    public static final int    INITIATOR_PAYLOAD_SIZE = 108;
    // header(4) + sender(4) + initiator payload(108) + mac1(16) + mac2(16)
    public static final int    INITIATOR_PACKET_SIZE  = 148;

    // ephemeral(32) + empty payload(0) + empty payload mac(16)
    public static final int    RESPONDER_PAYLOAD_SIZE = 48;
    // header(4) + sender(4) + receiver(4) + responder payload(48) + mac1(16) + mac2(16)
    public static final int    RESPONDER_PACKET_SIZE  = 92;

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
        ByteBuffer packet = ByteBuffer.allocate(INITIATOR_PACKET_SIZE);
        createInitiatorPacket(packet);
        byte[] bytePacket = packet.array();
        Log.i("wg", "generated packet ("+bytePacket.length+" bytes): "+ Utils.hexdump(bytePacket));

        return bytePacket;
    }

    public void createInitiatorPacket(ByteBuffer packet) throws ShortBufferException {
        if(packet.capacity() - packet.position() < INITIATOR_PACKET_SIZE) {
            throw new ShortBufferException("initiator packet is 148 bytes");
        }

        handshakeState.start();

        byte[] tai = Time.tai64n();
        packet.order(ByteOrder.LITTLE_ENDIAN);
        packet.putInt(initiatorHeader);

        packet.putInt(myIndex);

        byte[] payload = new byte[INITIATOR_PAYLOAD_SIZE];
        handshakeState.writeMessage(payload, 0, tai, 0, tai.length);
        packet.put(payload);

        Log.i("wg", "payload: "+ Utils.hexdump(payload));
        byte[] ephemeral = new byte[PUBLIC_KEY_SIZE];
        handshakeState.getLocalKeyPair().getPublicKey(ephemeral, 0);
        Log.i("wg", "ephemeral pubkey: "+Utils.hexdump(ephemeral));

        Log.i("wg", "packet so far: "+ Utils.hexdump(Arrays.copyOfRange(packet.array(), 0, 116)));


        byte[] serverKey = new byte[PUBLIC_KEY_SIZE];
        handshakeState.getRemotePublicKey().getPublicKey(serverKey, 0);

        try {
            Blake2sMessageDigest digest = new Blake2sMessageDigest(MAC_SIZE, null);

            Log.d("wg", "hashing serverKey: "+Utils.hexdump(serverKey));
            digest.update(serverKey);
            Log.d("wg", "hashing packet: "+Utils.hexdump(Arrays.copyOfRange(packet.array(), 0, 116)));
            digest.update(packet.array(), 0, 116);

            byte[] mac1 = digest.digest();
            packet.put(mac1, 0, MAC_SIZE);
            Log.i("wg", "complete mac1: "+ Utils.hexdump(mac1));
            Log.i("wg", "reduced mac1: "+ Utils.hexdump(Arrays.copyOfRange(mac1, 0, MAC_SIZE)));
        } catch (DigestException e) {
            e.printStackTrace();
        }
    }

    public boolean consumeResponsePacket(byte[] responsePacket) {
        return consumeResponsePacket(ByteBuffer.wrap(responsePacket));
    }

    public boolean consumeResponsePacket(ByteBuffer responsePacket) {
        responsePacket.order(ByteOrder.LITTLE_ENDIAN);
        responsePacket.mark();
        Log.d("wg", "offset begin: "+responsePacket.position());
        int header = responsePacket.getInt();
        if(header == responseHeader) {
            //FIXME: check the packet's length

            try {
                //go back to thr beginning of the packet
                responsePacket.reset();

                byte[] myPublicKey = new byte[PUBLIC_KEY_SIZE];
                handshakeState.getLocalKeyPair().getPublicKey(myPublicKey, 0);
                Blake2sMessageDigest digest = new Blake2sMessageDigest(MAC_SIZE, null);

                digest.update(myPublicKey);

                digest.update(responsePacket.array(), responsePacket.position(),
                        HEADER_SIZE + INDEX_SIZE * 2 + RESPONDER_PAYLOAD_SIZE);

                byte[] mac1 = Arrays.copyOfRange(responsePacket.array(),
                        responsePacket.position()+ HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE,
                        responsePacket.position()+ HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE + MAC_SIZE);
                if(!Arrays.equals(mac1, digest.digest())) {
                    Log.d("wg", "invalid mac1");
                    return false;
                }

                //FIXME: mac2 check deactivated for now
                if(false) {
                    byte[] mac2 = Arrays.copyOfRange(responsePacket.array(),
                            responsePacket.position()+HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE + MAC_SIZE,
                            responsePacket.position()+HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE + MAC_SIZE*2);
                    //???
                }

                //now that the MACs are validated, advance past the header
                int position = responsePacket.position();
                responsePacket.position(position+4);
                Log.d("wg", "offset after header: "+responsePacket.position());

                responderIndex = responsePacket.getInt();
                initiatorIndex = responsePacket.getInt();
                Log.d("wg", "offset after indexes: "+responsePacket.position());


                Log.i("wg", "response has initiator="+initiatorIndex+" and responder="+responderIndex);

                byte[] payload = new byte[0];
                handshakeState.readMessage(responsePacket.array(), responsePacket.position(), RESPONDER_PAYLOAD_SIZE,
                        payload, 0);

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

            channel.write(ByteBuffer.wrap(bytePacket, 0, bytePacket.length));
            Log.i("wg", "sent packet");
            Log.d("wg", "initiator state after send: "+handshakeState.getAction());


            ByteBuffer bb = ByteBuffer.allocate(RESPONDER_PACKET_SIZE);
            int bytesRead = channel.read(bb);
            bb.flip();

            Log.i("wg", "received("+bytesRead+" bytes): ");
            Log.d("wg", Utils.formatHexDump(bb.array(), 0, bytesRead));
            if(consumeResponsePacket(bb)) {
                    Log.i("wg", "the response packet was correct");
            }
            Log.d("wg", "initiator state after receive: "+handshakeState.getAction());

            handshakePair = handshakeState.split();
            Log.d("wg", "initiator state after split: "+handshakeState.getAction());

            Log.d("wg", "sending keep alive");
            //keep alive
            send(new byte[0], 0);
            Log.d("wg", "sent keep alive");


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
            bb.putInt(transportHeader);
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


        ByteBuffer bh = ByteBuffer.wrap(Arrays.copyOfRange(bb.array(), 0, 4));
        int header = bh.getInt();
        if(header == transportHeader) {

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
