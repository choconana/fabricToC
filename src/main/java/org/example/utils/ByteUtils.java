package org.example.utils;

import cn.hutool.core.util.ByteUtil;
import org.example.crypto.KeyConvertor;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

public class ByteUtils {

    public static final int uint15Num = 1 << 15;

    public static final int uint16Num = 1 << 16;

    public static final long uint31Num = 1L << 31;

    public static final long uint32Num = 1L << 32;

    public static void putUint16BigEndian(byte[] b, int v, int startPos) {
        if (v > uint16Num){
            throw new IllegalArgumentException(v + "greater than unsigned int16(" + uint16Num + ")");
        }
        byte[] b1 = ByteUtil.intToBytes(v, ByteOrder.BIG_ENDIAN);
        System.arraycopy(b1, 2, b, startPos, 2);
    }

    public static void putUint32BigEndian(byte[] b, long v, int startPos) {
        if (v > uint32Num) {
            throw new IllegalArgumentException(v + "greater than unsigned int32(" + uint32Num + ")");
        }
        byte[] b1 = ByteUtil.longToBytes(v, ByteOrder.BIG_ENDIAN);
        System.arraycopy(b1, 4, b, startPos, 4);
    }

    public static String toBinary(byte[] bytes, int len) {
        return String.format("%" + len + "s", new BigInteger(1, bytes).toString(2)).replace(' ', '0');
    }

    public static String formatBinary(String binary, int len) {
        return String.format("%" + len + "s", binary).replace(' ', '0');
    }

    public static byte[] binary2Bytes(String binary) {
        return new BigInteger(binary, 2).toByteArray();
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = KeyConvertor.createKey();
        int keylen = 33;
        byte[] b = new byte[keylen + 4];
        byte[] key = ((ECPrivateKey) keyPair.getPrivate()).getS().toByteArray();
        int offset = keylen - key.length;
        System.arraycopy(key, 0, b, offset, key.length);
        putUint32BigEndian(b, uint31Num + 1, keylen);
        System.out.println(b);
    }
}
