package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import lombok.Data;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by watermelon on 2019/04/11
 */
@Data
public abstract class Base<S> {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * 外部校验回调对象
     */
    private Validator validator;

    /**
     * 业务描述信息
     */
    private S businessDescInfo;

    private String jsonValue;
    private String signature;

    protected Model model;

    @Data
    public static class Model {
        private String jsonValue;
        private String signature;
    }

    public Base loadPublicKey(String pub) {

        try {
            this.publicKey = EncryptUtils.readPublicKey(pub);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        return this;
    }

    public Base loadPrivateKey(String pri) {
        try {
            this.privateKey = EncryptUtils.readPrivateKey(pri);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        return this;
    }

    public Base registerValidator(Validator validator) {
        this.validator = validator;
        return this;
    }

    public Base loadSignature(String signature) {
        this.signature = signature;
        return this;
    }

    public Base loadJsonValue(String jsonValue) {
        this.jsonValue = jsonValue;
        return this;
    }

    public abstract Model build();

    public abstract boolean verify();

}
