package com.trustkernel.uauth.utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

import java.io.IOException;
import java.util.Random;

public class CommonUtils {
    public static String random(int length) {
        if (length % 2 != 0) {
            throw new IllegalArgumentException("length must be even");
        }
        byte[] bytes = new byte[length / 2];
        Random random = new Random();
        random.nextBytes(bytes);
        return Hex.encodeHexString(bytes);
    }

    /**
     * 字节转16进制
     *
     * @param bytes
     * @return
     */
    public static String toHexString(byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }

    /**
     * 将16进制字符串转换为byte[]
     *
     * @param hexString
     * @return
     */
    public static byte[] fromHexString(String hexString) throws DecoderException {
        return Hex.decodeHex(hexString);
    }

    public static String readStringFromFile(String path) {
        try {
            return FileUtils.readFileToString(FileUtils.getFile(path), "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed read string from file");
        }
    }

}
