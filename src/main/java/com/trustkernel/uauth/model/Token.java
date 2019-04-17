package com.trustkernel.uauth.model;

import lombok.Data;

/**
 * Created by watermelon on 2019/04/16
 */
@Data
public class Token<U, B> {

    private String jsonValue;
    private String signature;

    @Data
    public static class TokenMeta<U, B> {
        private U userInfo;
        private BusinessDescriptionInformation<B> businessDescriptionInformation;
        private BiometricInformation biometricInformation;
    }

    @Data
    public static class BusinessDescriptionInformation<B> {
        private B scene;
        private String uid;
    }

    @Data
    public static class BiometricInformation {
        private String cpuId;
        private String fid;
    }
}


