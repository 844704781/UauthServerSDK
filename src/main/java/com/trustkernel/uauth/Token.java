package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import lombok.Data;

import java.nio.charset.Charset;

import java.util.LinkedHashMap;

/**
 * Created by watermelon on 2019/04/10
 */
public class Token {

    @Data
    public static class User {
        private String userId;
    }

    @Data
    public static class BusinessDescInfo {
        private String scene;
        private String uid;
    }

    @Data
    public static class BiometricInfo {
        private String cpuId;
        private String fid;
    }

    @Data
    public static class TokenModel {
        private String jsonValue;
        private String signature;

        public TokenModel(String jsonValue, String signature) {
            this.jsonValue = jsonValue;
            this.signature = signature;
        }
    }

    @Data
    public static class RequestParams {
        private String jsonValue;
        private String signature;
    }

    @Data
    public static class Params{
        private BusinessDescInfo businessDescInfo;
        private BiometricInfo biometricInfo;
        private TokenModel tokenModel;
    }

    @Data
    private static class SignParams{
        private User user;
        private BusinessDescInfo businessDescInfo;
        private BiometricInfo biometricInfo;


        public SignParams(User user, BusinessDescInfo businessDescInfo, BiometricInfo biometricInfo) {
            this.user = user;
            this.businessDescInfo = businessDescInfo;
            this.biometricInfo = biometricInfo;
        }
    }

    public static TokenModel sign(String privateKey, User user, BusinessDescInfo businessDescInfo, BiometricInfo biometricInfo) {
        SignParams signParams=new SignParams(user,businessDescInfo,biometricInfo);
        String jsonValue = JsonUtils.toJson(signParams, signParams.getClass());
        String signature = EncryptUtils.base64Encode(EncryptUtils.sign(jsonValue, privateKey));
        return new TokenModel(jsonValue, signature);
    }

    public static boolean verify(String authPub, String publicKey, RequestParams requestParams) {

        boolean f1 = EncryptUtils.verify(authPub, requestParams.getJsonValue(), requestParams.getSignature());
        Params params = JsonUtils.fromJson(requestParams.getJsonValue(), Params.class);
        TokenModel tokenModel = params.getTokenModel();

        boolean f2 = EncryptUtils.verify(publicKey, tokenModel.getJsonValue(), tokenModel.getSignature());
        SignParams signParams = JsonUtils.fromJson(tokenModel.getJsonValue(), SignParams.class);

        boolean f3 = params.getBiometricInfo().getCpuId().equals(signParams.getBiometricInfo().getCpuId())
                && params.getBiometricInfo().getFid().equals(signParams.getBiometricInfo().getFid())
                && params.getBusinessDescInfo().getScene().equals(signParams.getBusinessDescInfo().getScene())
                && params.getBusinessDescInfo().getUid().equals(signParams.getBusinessDescInfo().getUid());
        return f1 && f2 && f3;
    }
}
