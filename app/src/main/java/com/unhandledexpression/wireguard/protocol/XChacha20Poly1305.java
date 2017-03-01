package com.unhandledexpression.wireguard.protocol;

import com.southernstorm.noise.protocol.ChaChaPolyCipherState;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

import static com.southernstorm.noise.crypto.ChaChaCore.quarterRound;

/**
 * Created by geal on 01/03/2017.
 */

public class XChacha20Poly1305 {
    //key: 32 bytes, nonce: 24 bytes
    public static void encrypt(byte[] key, byte[] nonce, byte[] ad,
                        byte[] plaintext, int plaintextOffset, int plaintextLength,
                        byte[] ciphertext, int ciphertextOffset)
            throws ShortBufferException, InvalidKeyException {
        byte[] derived = new byte[32];

        HChaCha20(key, null, Arrays.copyOfRange(nonce, 0, 16), derived);
        ChaChaPolyCipherState chacha = new ChaChaPolyCipherState();
        chacha.initializeKey(derived, 0);

        ByteBuffer bNonce = ByteBuffer.wrap(nonce);
        bNonce.order(ByteOrder.LITTLE_ENDIAN);
        bNonce.position(16);
        chacha.setNonce(bNonce.getLong());

        chacha.encryptWithAd(ad, plaintext, plaintextOffset,
                ciphertext, ciphertextOffset, plaintextLength);

        Arrays.fill(derived, (byte)0);
        chacha.destroy();
    }

    public static void decrypt(byte[] key, byte[] nonce, byte[] ad,
                               byte[] ciphertext, int ciphertextOffset, int ciphertextLength,
                        byte[] plaintext, int plaintextOffset)
            throws ShortBufferException, InvalidKeyException, BadPaddingException {
        byte[] derived = new byte[32];

        HChaCha20(key, null, Arrays.copyOfRange(nonce, 0, 16), derived);
        ChaChaPolyCipherState chacha = new ChaChaPolyCipherState();
        chacha.initializeKey(derived, 0);

        ByteBuffer bNonce = ByteBuffer.wrap(nonce);
        bNonce.order(ByteOrder.LITTLE_ENDIAN);
        bNonce.position(16);
        chacha.setNonce(bNonce.getLong());

        chacha.decryptWithAd(ad, ciphertext, ciphertextOffset,
                plaintext, plaintextOffset, ciphertextLength);

        Arrays.fill(derived, (byte)0);
        chacha.destroy();
    }

    //key 32 bytes, constant 16 bytes, input 16 bytes, output 32 bytes
    public static void HChaCha20(byte[] key, byte[] constant, byte[] input, byte[] output)
            throws InvalidKeyException, ShortBufferException {
        if (key.length != 32) {
            throw new InvalidKeyException();
        }
        if (constant != null && constant.length != 16) {
            throw new InvalidKeyException();
        }
        if (input.length < 16 || output.length < 32) {
            throw new ShortBufferException();
        }

        int[] x = new int[16];

        if (constant == null) {
            x[0] = 0x61707865;
            x[1] = 0x3320646e;
            x[2] = 0x79622d32;
            x[3] = 0x6b206574;
        } else {
            ByteBuffer bb = ByteBuffer.wrap(constant);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            x[0] = bb.getInt();
            x[1] = bb.getInt();
            x[2] = bb.getInt();
            x[3] = bb.getInt();
        }

        ByteBuffer bKey = ByteBuffer.wrap(key);
        bKey.order(ByteOrder.LITTLE_ENDIAN);
        x[4]  = bKey.getInt();
        x[5]  = bKey.getInt();
        x[6]  = bKey.getInt();
        x[7]  = bKey.getInt();
        x[8]  = bKey.getInt();
        x[9]  = bKey.getInt();
        x[10] = bKey.getInt();
        x[11] = bKey.getInt();

        ByteBuffer bIn = ByteBuffer.wrap(input);
        bIn.order(ByteOrder.LITTLE_ENDIAN);
        x[12] = bIn.getInt();
        x[13] = bIn.getInt();
        x[14] = bIn.getInt();
        x[15] = bIn.getInt();

        for (int i = 0; i < 10; i++) {
            quarterRound(x, 0, 4, 8,  12);
            quarterRound(x, 1, 5, 9,  13);
            quarterRound(x, 2, 6, 10, 14);
            quarterRound(x, 3, 7, 11, 15);

            quarterRound(x, 0, 5, 10, 15);
            quarterRound(x, 1, 6, 11, 12);
            quarterRound(x, 2, 7, 8,  13);
            quarterRound(x, 3, 4, 9,  14);
        }

        ByteBuffer bOut = ByteBuffer.wrap(output);
        bOut.order(ByteOrder.LITTLE_ENDIAN);
        bOut.putInt(x[0]);
        bOut.putInt(x[1]);
        bOut.putInt(x[2]);
        bOut.putInt(x[3]);
        bOut.putInt(x[12]);
        bOut.putInt(x[13]);
        bOut.putInt(x[14]);
        bOut.putInt(x[15]);
    }
}
