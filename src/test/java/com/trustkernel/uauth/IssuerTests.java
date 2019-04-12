package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import lombok.Data;
import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;

/**
 * Created by watermelon on 2019/04/11
 */
@RunWith(JUnit4.class)
public class IssuerTests {

    /**
     * 设备端往服务器发的数据格式
     */
    @Data
    public static class RequestParams {
        private String jsonValue;
        private String signature;
    }

    @Data
    public static class Meta {

        private String business;
        private String data;
        private Issuer.Certificate certificate;
    }

    @Test
    public void generatorCert() throws IOException {

        /**
         * 大致流程:
         * Device                                                                       Server
         *
         * {                         请求服务器给下面数据签名
         *     deviceId:xxxx,       ---------------------------------------------->
         *     authPubKey:xxx
         * }                                                                            {
         *                                                                                jsonValue:'{authPubKey:xxx,deviceId:xxx}',
         *                                                                                signature:xxx
         *                          <---------------------------------------------      }
         *{
         *     jsonValue:'{
         *     deviceId:xxx,business:xxx
         *     ,cert:{jsonValue:authPubKey:xxx,deviceId:xxx}
         *     }'
         *     signature:xxx
         *}                         ----------------------------------------------->       1.验证cert 2.验证signature 3.验证deviceId
         *
         *
         *
         */

        String deviceId = "12312312423423412312";

        //业务公钥
        String auth_publicKey_path = "/home/watermelon/keypair/lib/pub01.pem";
        File file = FileUtils.getFile(auth_publicKey_path);
        String auth_publicKey = FileUtils.readFileToString(file, "UTF-8");

        //业务私钥
        String auth_privateKey_path = "/home/watermelon/keypair/lib/pri01.pem";
        File auth_privateKey_file = FileUtils.getFile(auth_privateKey_path);
        String auth_privateKey = FileUtils.readFileToString(auth_privateKey_file, "UTF-8");

        //SP私钥
        String sp_privateKey_path = "/home/watermelon/keypair/lib/pri02.pem";
        File sp_privateKey_file = FileUtils.getFile(sp_privateKey_path);
        String sp_privateKey = FileUtils.readFileToString(sp_privateKey_file, "UTF-8");

        //SP公钥
        String sp_publicKey_path = "/home/watermelon/keypair/lib/pub02.pem";
        File sp_publicKey_file = FileUtils.getFile(sp_publicKey_path);
        String sp_publicKey = FileUtils.readFileToString(sp_publicKey_file, "UTF-8");

        /**
         * 服务端:
         * 使用SP私钥签证书
         */
        Issuer<String> certificateIssuer = new Issuer<>();

        Issuer.Certificate certificate = certificateIssuer
                .loadPublicKey(auth_publicKey)
                .loadBusinessDescInfo(deviceId)
                .loadPrivateKey(sp_privateKey).build();

        /**
         * 客户端
         * 验证携带证书的数据
         */

        //1.准备业务数据
        Meta meta = new Meta();
        meta.setBusiness("Hello World");
        meta.setData(deviceId);
        meta.setCertificate(certificate);

        String metaJson = JsonUtils.toJson(meta, meta.getClass());
        //使用AuthPrivateKey签名数据
        String metaSignature = EncryptUtils.base64Encode(EncryptUtils.sign(metaJson, auth_privateKey));

        //发送请求数据
        RequestParams requestParams = new RequestParams();
        requestParams.setJsonValue(metaJson);
        requestParams.setSignature(metaSignature);

        /**
         * 服务端:
         * 服务器收到请求数据
         */
        Meta requestMeta = JsonUtils.fromJson(requestParams.getJsonValue(), Meta.class);

        //验证证书
        Issuer requestCertificateValidator = new Issuer();
        requestCertificateValidator.loadCertificate(requestMeta.getCertificate()).loadPublicKey(sp_publicKey);
        boolean v1 = requestCertificateValidator.verify();
        Assert.assertEquals(true, v1);

        //获取AuthKey公钥
        LinkedHashMap<String, String> map = JsonUtils.fromJson(requestMeta.getCertificate().getJsonValue(), LinkedHashMap.class);
        String data = map.get("data");
        String pubString = map.get("publicKey");

        Assert.assertEquals(auth_publicKey, pubString);
        Assert.assertEquals(requestParams.getJsonValue(), metaJson);
        Assert.assertEquals(requestParams.getSignature(), metaSignature);
        //准备业务数据有效性校验
        Validator valid = () -> meta.getData().equals(meta.getData());

        //使用AuthKey验证数据
        Issuer<String> validator = new Issuer<>();
        boolean v2 = validator.loadPublicKey(pubString)
                .loadJsonValue(requestParams.getJsonValue())
                .loadSignature(requestParams.getSignature())
                .registerValidator(valid)
                .verify();
        Assert.assertEquals(true, v2);
    }
}
