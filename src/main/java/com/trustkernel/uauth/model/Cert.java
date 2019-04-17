package com.trustkernel.uauth.model;

import lombok.Data;

/**
 * Created by watermelon on 2019/04/16
 */
@Data
public class Cert {

    private String jsonValue;
    private String signature;

    public Cert(String jsonValue, String signature) {
        this.jsonValue = jsonValue;
        this.signature = signature;
    }


    @Data
    public static class CertMeta {
        private Integer type;
        private String deviceId;
        private String publicKey;
        private String uid;
        private String fid;
        private String tee_n;
        private String tee_v;
        private String fp_n;
        private String fp_v;
    }
}
