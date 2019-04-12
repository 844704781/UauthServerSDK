package com.trustkernel.uauth.utils;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class EncryptUtils {

    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA/PSS";

    /**
     * RFC2045规定76位换行，openssl是64位换行,此处已openssl为准
     */
   private static final Base64 base64=new Base64(64);

    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 签名
     *
     * @param data
     * @param privateKey
     * @return
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            init();
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1));
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed signature ");
        }
    }

    public static byte[] sign(String data, String privateKey) {
        PrivateKey privateKey1;
        try {
            privateKey1 = readPrivateKey(privateKey);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed format privateKey");
        }
        byte[] original;
        try {
            original = data.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed format privateKey");
        }
        return sign(original, privateKey1);
    }

    /**
     * 验签
     *
     * @param publicKey
     * @param data
     * @param sign
     * @return
     */
    public static boolean verify(PublicKey publicKey, byte[] data, byte[] sign) {
        try {
            init();
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1));
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sign);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(PublicKey publicKey, String data, String signature) {
        return verify(publicKey, data.getBytes(), EncryptUtils.base64Decode(signature));
    }

    public static boolean verify(PublicKey publicKey, String data, byte[] signature) {

        return verify(publicKey, data.getBytes(), signature);
    }


    public static boolean verify(String pubkey, String data, String sigature) {
        PublicKey publicKey;
        try {
            publicKey = EncryptUtils.readPublicKey(pubkey);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed format publicKey");
        }
        return verify(publicKey, data, EncryptUtils.base64Decode(sigature));
    }


    /**
     * 对数据进行base64编码
     *
     * @param input
     * @return
     */
    public static String base64Encode(byte[] input) {
      // return new String(org.bouncycastle.util.encoders.Base64.encode(input),Charset.forName("UTF-8"));
        //return  Base64.encodeBase64String(input);
        //return new String(new Base64().encode(input), Charset.forName("UTF-8"));
        return base64.encodeToString(input).replaceAll("\r","");
    }

    /**
     * 对数据进行base64解码
     *
     * @param data
     * @return
     * @throws IOException
     */
    public static byte[] base64Decode(String data) {
        //不换行
        // return org.bouncycastle.util.encoders.Base64.decode(data);
        //return Base64.decodeBase64(data);
        //return new Base64().decode(data);
        return base64.decode(data);
    }

    /**
     * 读取openssl生层的私钥
     *
     * @param pemEncoding
     * @return
     * @throws IOException
     */
    public static PrivateKey readPrivateKey(String pemEncoding)
            throws IOException {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));
        PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
        return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
    }

    /**
     * 读取openssl生成的公钥
     *
     * @param pemEncoding
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public static PublicKey readPublicKey(String pemEncoding)
            throws IOException {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));
        SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) parser.readObject();
        return new JcaPEMKeyConverter().getPublicKey(publicKeyInfo);
    }

}
