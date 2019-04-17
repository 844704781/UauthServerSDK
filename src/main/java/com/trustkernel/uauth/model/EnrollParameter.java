package com.trustkernel.uauth.model;

import lombok.Data;

/**
 * Created by watermelon on 2019/04/15
 */
@Data
public class EnrollParameter {



    private String jsonValue;
    private String signature;

    private String businessJsonValue;
    private String businessPublicKeySignature;
    private String applicationJsonValue;
    private String applicationGlobalPublicKeySignature;

    /**
     * 上传ask,authKey,soter生成的数据
     */
    @Data
    public static class Meta{
        private String pub_key;
        private String cpu_id;
        private Integer counter;
        private String uid;
    }

    /**
     * 上传业务数据时jsonValue的元数据
     */
    @Data
    public static class BusinessMeta{
        private String raw;
        private String fid;
        private Integer counter;
        private String tee_n;
        private String tee_v;
        private String fp_n;
        private String fp_v;
        private String cpuId;
        private String uid;
    }
}
