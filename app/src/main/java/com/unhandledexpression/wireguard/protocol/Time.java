package com.unhandledexpression.wireguard.protocol;

import android.util.Log;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Created by geal on 25/02/2017.
 */

public class Time {
    public static byte[] tai64n() {
        ByteBuffer b = ByteBuffer.allocate(12);

        long seconds = System.currentTimeMillis() / 1000l;
        Long prefix = new Long("4611686018427387914");
        Long tai = prefix + seconds;

        b.order(ByteOrder.BIG_ENDIAN);
        b.putLong(tai.longValue());

        int nanos = (int)System.nanoTime();
        b.putInt(nanos);

        return b.array();
    }
}
