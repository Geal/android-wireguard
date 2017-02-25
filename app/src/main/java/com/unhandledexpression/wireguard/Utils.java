package com.unhandledexpression.wireguard;

/**
 * Created by geal on 25/02/2017.
 */

public class Utils {
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String hexdump(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
