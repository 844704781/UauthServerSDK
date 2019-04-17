package com.trustkernel.uauth.model;

import lombok.Data;

/**
 * Created by watermelon on 2019/04/15
 */
@Data
public class AuthenticateParameter<U, B> {
    private String cpuId;
    private String fid;
    private Token<U, B> token;
    private Cert applicationCert;
    private Cert businessCert;
}
