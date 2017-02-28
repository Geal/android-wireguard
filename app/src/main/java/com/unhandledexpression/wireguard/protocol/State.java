package com.unhandledexpression.wireguard.protocol;

import com.southernstorm.noise.crypto.Blake2sMessageDigest;
import com.southernstorm.noise.protocol.ChaChaPolyCipherState;
import com.southernstorm.noise.protocol.CipherStatePair;
import com.southernstorm.noise.protocol.DHState;
import com.southernstorm.noise.protocol.HandshakeState;
import com.southernstorm.noise.protocol.Noise;
import com.unhandledexpression.wireguard.Utils;

import android.util.Log;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;


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
    public static final int    COUNTER_SIZE           = 8;
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
    // maybe make this configurable
    public static final int    MAX_PACKET_SIZE        = 512;

    public HandshakeState  handshakeState;
    public long            sendCounter    = 0;
    public long            receiveCounter = 0;
    public int             theirIndex;
    public int             myIndex;
    public CipherStatePair handshakePair;
    public byte[]          presharedKey   = null;
    public byte[]          currentCookie  = null;

    public State(Configuration configuration, int role) {
        Random rand = new SecureRandom();
        myIndex = rand.nextInt();

        try {
            handshakeState = new HandshakeState("Noise_IK_25519_ChaChaPoly_BLAKE2s", role);
            handshakeState.setPrologue(PROLOGUE.getBytes(), 0, PROLOGUE.length());

            handshakeState.getLocalKeyPair().setPrivateKey(configuration.myPrivateKey, 0);
            handshakeState.getRemotePublicKey().setPublicKey(configuration.theirPublicKey,0);

            handshakeState.start();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public State(byte[] myPrivateKey, byte[] theirPublicKey, int role) {

        Random rand = new SecureRandom();
        myIndex = rand.nextInt();

        try {
            handshakeState = new HandshakeState("Noise_IK_25519_ChaChaPoly_BLAKE2s", role);
            handshakeState.setPrologue(PROLOGUE.getBytes(), 0, PROLOGUE.length());

            handshakeState.getLocalKeyPair().setPrivateKey(myPrivateKey, 0);
            handshakeState.getRemotePublicKey().setPublicKey(theirPublicKey, 0);

            handshakeState.start();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public State(byte[] myPrivateKey, byte[] theirPublicKey, byte[] _presharedKey, int role) {

        Random rand = new SecureRandom();
        myIndex = rand.nextInt();
        presharedKey = _presharedKey;

        try {
            handshakeState = new HandshakeState("NoisePSK_IK_25519_ChaChaPoly_BLAKE2s", role);
            handshakeState.setPrologue(PROLOGUE.getBytes(), 0, PROLOGUE.length());

            handshakeState.getLocalKeyPair().setPrivateKey(myPrivateKey, 0);
            handshakeState.getRemotePublicKey().setPublicKey(theirPublicKey, 0);
            handshakeState.setPreSharedKey(presharedKey, 0, presharedKey.length);

            handshakeState.start();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void endHandshake() {
        handshakePair = handshakeState.split();
    }

    public boolean hasPSK() {
        return presharedKey != null;
    }

    public boolean hasCookie() {
        return currentCookie != null;
    }

    public boolean isCookieExpired() {
        //FIXME: implement timeouts
        return false;
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
            Blake2sMessageDigest digest = null;
            if (hasPSK()) {
                digest = new Blake2sMessageDigest(MAC_SIZE, presharedKey);
            } else {
                digest = new Blake2sMessageDigest(MAC_SIZE, null);
            }

            Log.d("wg", "hashing serverKey: "+Utils.hexdump(serverKey));
            digest.update(serverKey);
            Log.d("wg", "hashing packet: "+Utils.hexdump(Arrays.copyOfRange(packet.array(), 0, 116)));
            digest.update(packet.array(), 0, 116);

            byte[] mac1 = digest.digest();
            packet.put(mac1, 0, MAC_SIZE);
            Log.i("wg", "complete mac1: " + Utils.hexdump(mac1));
            Log.i("wg", "reduced mac1: " + Utils.hexdump(Arrays.copyOfRange(mac1, 0, MAC_SIZE)));

            if(hasCookie() && !isCookieExpired()) {
                Blake2sMessageDigest digest2 = new Blake2sMessageDigest(MAC_SIZE, currentCookie);
                digest2.update(packet.array(), 0, HEADER_SIZE+INDEX_SIZE+INITIATOR_PAYLOAD_SIZE+MAC_SIZE);
                byte[] mac2 = digest2.digest();
                packet.put(mac2, 0, MAC_SIZE);
            }
        } catch (DigestException e) {
            e.printStackTrace();
        }
    }

    public boolean consumeInitiatorPacket(byte[] initiatorPacket) {
        return consumeInitiatorPacket(ByteBuffer.wrap(initiatorPacket));
    }

    public boolean consumeInitiatorPacket(ByteBuffer initiatorPacket) {
        initiatorPacket.order(ByteOrder.LITTLE_ENDIAN);
        initiatorPacket.mark();
        int header = initiatorPacket.getInt();
        if(header == initiatorHeader) {
            //FIXME: check the packet's length

            try {
                //go back to the beginning of the packet
                initiatorPacket.reset();

                byte[] myPublicKey = new byte[PUBLIC_KEY_SIZE];
                handshakeState.getLocalKeyPair().getPublicKey(myPublicKey, 0);

                Blake2sMessageDigest digest = null;
                if (hasPSK()) {
                    digest = new Blake2sMessageDigest(MAC_SIZE, presharedKey);
                } else {
                    digest = new Blake2sMessageDigest(MAC_SIZE, null);
                }

                digest.update(myPublicKey);

                digest.update(initiatorPacket.array(), initiatorPacket.position(),
                        HEADER_SIZE + INDEX_SIZE + INITIATOR_PAYLOAD_SIZE);

                byte[] mac1 = Arrays.copyOfRange(initiatorPacket.array(),
                        initiatorPacket.position()+ HEADER_SIZE + INDEX_SIZE + INITIATOR_PAYLOAD_SIZE,
                        initiatorPacket.position()+ HEADER_SIZE + INDEX_SIZE + INITIATOR_PAYLOAD_SIZE + MAC_SIZE);
                if(!Arrays.equals(mac1, digest.digest())) {
                    Log.d("wg", "invalid mac1");
                    return false;
                }

                if(hasCookie()) {
                    Blake2sMessageDigest digest2 = new Blake2sMessageDigest(MAC_SIZE, currentCookie);
                    digest2.update(initiatorPacket.array(), initiatorPacket.position(),
                            HEADER_SIZE+INDEX_SIZE+INITIATOR_PAYLOAD_SIZE+MAC_SIZE);
                    byte[] mac2 = Arrays.copyOfRange(initiatorPacket.array(),
                            initiatorPacket.position() + HEADER_SIZE + INDEX_SIZE + INITIATOR_PAYLOAD_SIZE + MAC_SIZE,
                            initiatorPacket.position() + HEADER_SIZE + INDEX_SIZE + INITIATOR_PAYLOAD_SIZE + MAC_SIZE*2);
                    if (!Arrays.equals(mac2, digest2.digest())) {
                        Log.d("wg", "invalid mac1");
                        return false;
                    }
                }

                //now that the MACs are validated, advance past the header
                int position = initiatorPacket.position();
                initiatorPacket.position(position+4);
                Log.d("wg", "offset after header: "+initiatorPacket.position());

                myIndex = initiatorPacket.getInt();
                Log.d("wg", "offset after index: "+initiatorPacket.position());


                Log.i("wg", "initiator packet has initiator="+myIndex);

                Log.i("wg", "handshake state before decryption: "+handshakeState.getAction());
                byte[] payload = new byte[12];
                handshakeState.readMessage(initiatorPacket.array(), initiatorPacket.position(), INITIATOR_PAYLOAD_SIZE,
                        payload, 0);
                Log.i("wg", "got timestamp: "+Utils.formatHexDump(payload, 0, 12));

                Log.i("wg", "handshake state after decryption: "+handshakeState.getAction());

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

    public byte[] createResponsePacket() throws ShortBufferException {
        ByteBuffer packet = ByteBuffer.allocate(RESPONDER_PACKET_SIZE);
        createResponsePacket(packet);
        byte[] bytePacket = packet.array();
        Log.i("wg", "generated packet ("+bytePacket.length+" bytes): "+ Utils.hexdump(bytePacket));

        return bytePacket;
    }

    public void createResponsePacket(ByteBuffer packet) throws ShortBufferException {
        if(packet.capacity() - packet.position() < RESPONDER_PACKET_SIZE) {
            throw new ShortBufferException("initiator packet is 148 bytes");
        }

        packet.order(ByteOrder.LITTLE_ENDIAN);
        int position = packet.position();
        packet.putInt(responseHeader);

        packet.putInt(myIndex);

        //FIXME: verify we know this index?
        packet.putInt(theirIndex);

        byte[] payload = new byte[RESPONDER_PAYLOAD_SIZE];
        handshakeState.writeMessage(payload, 0, new byte[0], 0, 0);
        packet.put(payload);

        Log.i("wg", "payload: "+ Utils.hexdump(payload));
        byte[] ephemeral = new byte[PUBLIC_KEY_SIZE];
        handshakeState.getLocalKeyPair().getPublicKey(ephemeral, 0);
        Log.i("wg", "ephemeral pubkey: "+Utils.hexdump(ephemeral));

        Log.i("wg", "packet so far: "+ Utils.hexdump(Arrays.copyOfRange(packet.array(), position,
                position + HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE)));


        byte[] serverKey = new byte[PUBLIC_KEY_SIZE];
        handshakeState.getRemotePublicKey().getPublicKey(serverKey, 0);

        try {
            Blake2sMessageDigest digest = null;
            if (hasPSK()) {
                digest = new Blake2sMessageDigest(MAC_SIZE, presharedKey);
            } else {
                digest = new Blake2sMessageDigest(MAC_SIZE, null);
            }

            Log.d("wg", "hashing serverKey: "+Utils.hexdump(serverKey));
            digest.update(serverKey);
            Log.d("wg", "hashing packet: "+Utils.hexdump(Arrays.copyOfRange(packet.array(), position,
                    position + HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE)));
            digest.update(packet.array(), position,
                    position + HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE);

            byte[] mac1 = digest.digest();
            packet.put(mac1, 0, MAC_SIZE);
            Log.i("wg", "complete mac1: " + Utils.hexdump(mac1));
            Log.i("wg", "reduced mac1: " + Utils.hexdump(Arrays.copyOfRange(mac1, 0, MAC_SIZE)));

            if(hasCookie() && !isCookieExpired()) {
                Blake2sMessageDigest digest2 = new Blake2sMessageDigest(MAC_SIZE, currentCookie);
                digest2.update(packet.array(), 0, HEADER_SIZE+INDEX_SIZE*2+RESPONDER_PAYLOAD_SIZE+MAC_SIZE);
                byte[] mac2 = digest2.digest();
                packet.put(mac2, 0, MAC_SIZE);
            }
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

                Blake2sMessageDigest digest = null;
                if (hasPSK()) {
                    digest = new Blake2sMessageDigest(MAC_SIZE, presharedKey);
                } else {
                    digest = new Blake2sMessageDigest(MAC_SIZE, null);
                }

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

                if(hasCookie()) {
                    Blake2sMessageDigest digest2 = new Blake2sMessageDigest(MAC_SIZE, currentCookie);
                    digest2.update(responsePacket.array(), responsePacket.position(),
                            HEADER_SIZE+INDEX_SIZE*2+RESPONDER_PAYLOAD_SIZE+MAC_SIZE);
                    byte[] mac2 = Arrays.copyOfRange(responsePacket.array(),
                            responsePacket.position() + HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE + MAC_SIZE,
                            responsePacket.position() + HEADER_SIZE + INDEX_SIZE*2 + RESPONDER_PAYLOAD_SIZE + MAC_SIZE*2);
                    if (!Arrays.equals(mac2, digest2.digest())) {
                        Log.d("wg", "invalid mac1");
                        return false;
                    }
                }

                //now that the MACs are validated, advance past the header
                int position = responsePacket.position();
                responsePacket.position(position+4);
                Log.d("wg", "offset after header: "+responsePacket.position());

                theirIndex = responsePacket.getInt();
                myIndex = responsePacket.getInt();
                Log.d("wg", "offset after indexes: "+responsePacket.position());


                Log.i("wg", "response has initiator="+myIndex+" and responder="+theirIndex);

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

    /*
    public void initiate(DatagramChannel _channel) {
        channel = _channel;
        try {
            Log.d("wg", "initiator state before send: "+handshakeState.getAction());
            byte[] bytePacket = createInitiatorPacket();

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
    */

    public byte[] send(byte[] data, int offset, int length) throws IOException, ShortBufferException {
        ChaChaPolyCipherState sender = (ChaChaPolyCipherState) handshakePair.getSender();
        ByteBuffer bb = ByteBuffer.allocate(MAX_PACKET_SIZE);

        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(transportHeader);
        bb.putInt(theirIndex);

        //long counter = sender.n;
        bb.putLong(sendCounter);

        byte[] packet = bb.array();
        Log.i("wg", "header with counter("+sendCounter+"): "+Utils.hexdump(Arrays.copyOfRange(packet, 0, 16)));
        Log.i("wg", "to copy: "+length);
        sender.setNonce(sendCounter);
        int copied = sender.encryptWithAd(null,
                data, offset,
                packet, HEADER_SIZE + INDEX_SIZE + COUNTER_SIZE, length);

        Log.i("wg", "will send["+sendCounter+"] ("+(copied+16)+" bytes): "+Utils.hexdump(Arrays.copyOfRange(packet, 0, copied+16)));

        sendCounter++;
        return Arrays.copyOfRange(packet, 0, copied+16);
    }

    public byte[] receive(ByteBuffer bb, int bytesRead) throws IOException, ShortBufferException, BadPaddingException {
        bb.order(ByteOrder.LITTLE_ENDIAN);

        bb.mark();
        int header = bb.getInt();
        if (header == transportHeader) {

            int remoteIndex = bb.getInt();
            //FIXME: check if it is in the acceptable range
            long currentReceiveCounter  = bb.getLong();
            Log.d("wg", "got remote index: "+remoteIndex);
            Log.d("wg", "got receive counter: "+currentReceiveCounter);
            Log.d("wg", "last receive counter: "+receiveCounter);
            //FIXME: what if the order is wrong?
            receiveCounter = currentReceiveCounter;

            ChaChaPolyCipherState receiver = (ChaChaPolyCipherState) handshakePair.getReceiver();
            //Log.d("wg", "handshake pair receiver counter: "+ receiver.n);
            receiver.setNonce(currentReceiveCounter);

            byte[] payload = new byte[bytesRead - HEADER_SIZE - INDEX_SIZE - COUNTER_SIZE - MAC_SIZE];
            int decrypted = handshakePair.getReceiver().decryptWithAd(null, bb.array(), bb.position(),
                    payload, 0, bytesRead - HEADER_SIZE - INDEX_SIZE - COUNTER_SIZE);

            Log.i("wg", "decrypted packet("+decrypted+" bytes of payload) with counter: "+receiveCounter);
            return payload;
        } else if (header == initiatorHeader) {
            bb.reset();
            if(consumeInitiatorPacket(bb)) {
                Log.i("wg", "the initiator packet was correct");
                //handshakePair = handshakeState.split();
                //Log.d("wg", "responder state after split: "+handshakeState.getAction());
            } else {
                //FIXME: return an error here
                Log.i("wg", "the initiator packet was incorrect");
            }
            return null;
        } else if (header == cookieReplyHeader) {
            Log.d("wg", "UNIMPLEMENTED");
            return null;
        } else if (header == responseHeader) {
            bb.reset();
            if(consumeResponsePacket(bb)) {
                Log.i("wg", "the response packet was correct");
                endHandshake();
                Log.d("wg", "initiator state after split: "+handshakeState.getAction());


            } else {
                //FIXME: return an error here
                Log.i("wg", "the response packet was incorrect");
            }
            return null;
        } else {
            Log.d("wg", "invalid transport header packet");
            return null;
        }
    }

    public static void exampleRun(State aliceState, State bobState) {
        try {
            byte[] initiatorPacket = aliceState.createInitiatorPacket();

            Log.i("wg", "Alice created initiator packet:\n"+Utils.formatHexDump(initiatorPacket, 0, initiatorPacket.length));


            byte[] tai = bobState.receive(ByteBuffer.wrap(initiatorPacket), initiatorPacket.length);
            assert tai.length == 12;

            Log.i("wg", "Bob received packet");

            byte[] responsePacket = bobState.createResponsePacket();
            bobState.endHandshake();

            Log.i("wg", "Bob created response packet:\n"+Utils.formatHexDump(responsePacket, 0, responsePacket.length));

            byte[] empty = aliceState.receive(ByteBuffer.wrap(responsePacket), responsePacket.length);
            assert empty.length == 0;

            byte[] message = "hello world!".getBytes();
            byte[] packet  = aliceState.send(message, 0, message.length);

            Log.i("wg", "Alice sends packet:\n"+Utils.formatHexDump(packet, 0, packet.length));

            byte[] received = bobState.receive(ByteBuffer.wrap(packet), packet.length);
            Log.i("wg", "Bob decrypted:\n"+new String(received, Charset.forName("UTF-8")));

            assert message == received;

            Log.i("wg", "*** DONE ***");
        } catch (ShortBufferException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void basicTest() {
        Log.i("wg", "*** PROTOCOL TEST CASE ***");
        try {
            DHState curve = Noise.createDH("25519");

            byte[] alicePrivate = new byte[32];
            byte[] alicePublic  = new byte[32];
            byte[] bobPrivate   = new byte[32];
            byte[] bobPublic    = new byte[32];

            curve.generateKeyPair();
            curve.getPrivateKey(alicePrivate, 0);
            curve.getPublicKey(alicePublic, 0);

            curve.generateKeyPair();
            curve.getPrivateKey(bobPrivate, 0);
            curve.getPublicKey(bobPublic, 0);

            Log.i("wg", "generated keys");

            State aliceState = new State(alicePrivate, bobPublic, HandshakeState.INITIATOR);
            State bobState   = new State(bobPrivate, alicePublic, HandshakeState.RESPONDER);

            Log.i("wg", "generated states");

            exampleRun(aliceState, bobState);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void preSharedKeyTest() {
        Log.i("wg", "*** PROTOCOL WITH PRE-SHARED KEY TEST CASE ***");
        try {
            DHState curve = Noise.createDH("25519");

            byte[] alicePrivate = new byte[32];
            byte[] alicePublic = new byte[32];
            byte[] bobPrivate = new byte[32];
            byte[] bobPublic = new byte[32];
            byte[] preSharedKey = new byte[32];

            curve.generateKeyPair();
            curve.getPrivateKey(alicePrivate, 0);
            curve.getPublicKey(alicePublic, 0);

            curve.generateKeyPair();
            curve.getPrivateKey(bobPrivate, 0);
            curve.getPublicKey(bobPublic, 0);

            Noise.random(preSharedKey);

            Log.i("wg", "generated keys");

            State aliceState = new State(alicePrivate, bobPublic, preSharedKey, HandshakeState.INITIATOR);
            State bobState = new State(bobPrivate, alicePublic, preSharedKey, HandshakeState.RESPONDER);

            Log.i("wg", "generated states");

            exampleRun(aliceState, bobState);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

