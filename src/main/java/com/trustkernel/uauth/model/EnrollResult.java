package com.trustkernel.uauth.model;

import lombok.Data;

/**
 * Created by watermelon on 2019/04/15
 */
@Data
public class EnrollResult<U, B> {

    private Token token;
    private Cert businessCert;
    private Cert applicationGlobalKeyCert;

}
