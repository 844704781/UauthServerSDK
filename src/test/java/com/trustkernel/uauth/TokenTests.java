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

/**
 * Created by watermelon on 2019/04/11
 */
@RunWith(JUnit4.class)
public class TokenTests {
    @Data
    public class User {
        private String userId = "111111111111111";
        private String nonce;
    }

    @Data
    public class BiometricInfo {
        private String cpuId;
        private String fid;
    }

    @Data
    public class BusinessDescInfo {
        private String uid;
        private String scene;
    }

    @Data
    public static class RequestParams {
        private String jsonValue;
        private String signature;
    }

    @Data
    public static class Meta {
        private String userId;
        private String nonce;
        private BiometricInfo biometricInfo;
        private BusinessDescInfo businessDescInfo;
    }

    @Data
    public static class RequestBusinessMeta {
        private String business;
        private BusinessDescInfo businessDescInfo;
        private BiometricInfo biometricInfo;
        private Token.TokenModel tokenModel;
    }

    @Test
    public void testToken() throws IOException {
        /**
         * 大致流程
         * Device                                                                                       Server
         * {
         *     userId:xxx           ------------------------------------------------------->            生成userId与nonce的绑定关系
         * }                                                                                            {
         * {                         < ------------------------------------------------------                nonce:xxx
         *     jsonValue:'{user:{userId:xxx,nonce:xxx},
         *              businessDescInfo:{scene:xxx,uid:xxx},
         *              biometricInfo:{cpuId:xxx,fid:xxx}}',  ----------------------------->            验证nonce,生成token                                                                                             }
         *     signature:xxx(auth_pub签)
         * }
         *                                                                                            token:{
         *                          <-------------------------------------------------------            jsonValue:'{user:{userId:xxx},
         *                                                                                                  businessDescInfo:{scene:xxx,uid:xxx},
         *                                                                                                  biometricInfo:{cpuId:xxx,fid:xxx}}',
         *                                                                                              signature:xxx(sp_pri签)
         *                                                                                             }
         *
         *{
         *  jsonValue:'{business:xxx,
         *      businessDescInfo:{scene:xxx,uid:xxx},
         *      biometricInfo:{cpuId:xxx,fid:xxx}}',
         *      token:{
         *          jsonValue:'{
         *          user:{userId:xxx},
         *          businessDescInfo:
         *          {scene:xxx,uid:xxx},                    ----------------------------------->       1.使用auth_pub验签 2.再使用sp_pub验签token 3.再验证特征信息
         *          biometricInfo:{cpuId:xxx,fid:xxx}',
         *          signature:xxx(sp_pri签}'                                                           4.业务操作
         *      },
         *  signature:xxx(auth_pri签)
         *}
         *
         */

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
         * 生成nonce
         */
        String nonce = Challenge.generateNonce();

        /**
         * 客户端请求nonce
         */
        User user = new User();
        user.setNonce(nonce);

        //返回nonce给客户端
        /**
         * 客户端发送获取token的请求
         */
        //伪造业务描述
        BusinessDescInfo businessDescInfo = new BusinessDescInfo();
        businessDescInfo.setScene("0");
        businessDescInfo.setUid("231231");

        //伪造生物特征
        BiometricInfo biometricInfo = new BiometricInfo();
        biometricInfo.setCpuId("123123");
        biometricInfo.setFid("1231231434343");

        /**
         * 客户端:
         * 发送获取token请求数据,使用AuthPrivateKey签名
         */
        Meta meta = new Meta();
        meta.setNonce(nonce);
        meta.setUserId(user.getUserId());
        meta.setBiometricInfo(biometricInfo);
        meta.setBusinessDescInfo(businessDescInfo);

        String metaValue = JsonUtils.toJson(meta, meta.getClass());
        String metaSignature = EncryptUtils.base64Encode(EncryptUtils.sign(metaValue, auth_privateKey));
        boolean v0 = EncryptUtils.verify(auth_publicKey, metaValue, metaSignature);
        Assert.assertEquals(true, v0);
        RequestParams requestParams = new RequestParams();
        requestParams.setJsonValue(metaValue);
        requestParams.setSignature(metaSignature);

        /**
         * 服务器端使用AuthPubKey验签
         */

        Assert.assertEquals(requestParams.getJsonValue(), metaValue);
        Assert.assertEquals(metaSignature, requestParams.getSignature());
        Token token = new Token();
        boolean v1 = token.loadPublicKey(auth_publicKey)
                .loadSignature(requestParams.getSignature())
                .loadJsonValue(requestParams.getJsonValue())
                .verify();

        Assert.assertEquals(true, v1);

        /**
         * 验证nonce,验证完清除nonce
         */
        Meta requestMeta = JsonUtils.fromJson(requestParams.getJsonValue(), Meta.class);
        Assert.assertEquals(requestMeta.nonce, user.getNonce());
        user.setNonce(null);

        /**
         * 服务器:
         * 签发token
         */

        Token<User, BusinessDescInfo, BiometricInfo> token01 = new Token<>();
        Token.TokenModel tokenModel = token01.loadPrivateKey(sp_privateKey).loadUserInfo(user).loadBusinessDescInfo(businessDescInfo)
                .loadBiometricInfo(biometricInfo)
                .build();

        /**
         * 客户端收到token,构建业务请求数据,使用authKey私钥签名,发送给服务器
         */

        RequestBusinessMeta requestBusinessMeta = new RequestBusinessMeta();
        requestBusinessMeta.setBiometricInfo(biometricInfo);
        requestBusinessMeta.setBusiness("Hello world");
        requestBusinessMeta.setBusinessDescInfo(businessDescInfo);
        requestBusinessMeta.setTokenModel(tokenModel);

        String jsonValue = JsonUtils.toJson(requestBusinessMeta, requestBusinessMeta.getClass());
        String signature = EncryptUtils.base64Encode(EncryptUtils.sign(jsonValue, auth_privateKey));

        RequestParams requestParams1 = new RequestParams();
        requestParams1.setSignature(signature);
        requestParams1.setJsonValue(jsonValue);

        /**
         * 服务器收到数据,先使用AuthKey验签，再验证token的有效性
         */

        Token token02 = new Token();
        token02.loadJsonValue(requestParams1.getJsonValue());
        token02.loadSignature(requestParams1.getSignature());
        token02.loadPublicKey(auth_publicKey);
        boolean v2 = token02.verify();

        Assert.assertEquals(true, v2);

        RequestBusinessMeta requestBusinessMeta1 = JsonUtils.fromJson(requestParams1.getJsonValue(), RequestBusinessMeta.class);
        Token token03 = new Token();
        token03.loadTokenModel(requestBusinessMeta.getTokenModel())
                .loadPublicKey(sp_publicKey)
                .registerValidator(() -> {
                    return requestBusinessMeta1.getBiometricInfo().getCpuId().equals(biometricInfo.getCpuId());
                });
        boolean v3 = token03.verify();
        Assert.assertEquals(true, v3);
        System.out.println("客户端发过来的业务数据:" + requestBusinessMeta1.getBusiness());
    }
}
