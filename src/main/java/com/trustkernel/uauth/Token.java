package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;

import java.nio.charset.Charset;

import java.util.LinkedHashMap;

/**
 * Created by watermelon on 2019/04/10
 */
public class Token<U, S, K> extends Base<S> {

    private TokenModel tokenModel;

    private Validator validator = () -> true;

    /**
     * 用户信息
     */
    private U userInfo;

    /**
     * 生物特征信息
     */
    private K biometricInfo;

    public class TokenModel extends Model {

    }

    @Override
    public Token loadPrivateKey(String pri) {
        return (Token) super.loadPrivateKey(pri);
    }

    @Override
    public Token loadPublicKey(String pub) {
        return (Token) super.loadPublicKey(pub);
    }

    @Override
    public TokenModel build() {
        /**
         * 验证参数
         */

        /**
         * 生成tokenModel对象
         */
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put("userInfo", this.userInfo);
        map.put("businessDescInfo", this.getBusinessDescInfo());
        map.put("biometricInfo", this.biometricInfo);
        if (this.tokenModel == null) {
            this.tokenModel = new TokenModel();
        }
        this.tokenModel.setJsonValue(JsonUtils.toJson(map, map.getClass()));
        this.tokenModel.setSignature(EncryptUtils
                .base64Encode(EncryptUtils.sign(this.tokenModel.getJsonValue().getBytes(Charset.forName("UTF-8")), this.getPrivateKey())));
        return this.tokenModel;
    }

    @Override
    public Token registerValidator(Validator validator) {
        return (Token) super.registerValidator(validator);
    }

    @Override
    public boolean verify() {
        /**
         * 验证参数
         */

        /**
         * 验证tokenModel对象
         */
        if (this.tokenModel == null) {
            return EncryptUtils.verify(this.getPublicKey(), this.getJsonValue(), this.getSignature());
        } else {
            return EncryptUtils.verify(this.getPublicKey(), this.tokenModel.getJsonValue(), this.tokenModel.getSignature()) && this.validator
                    .verify();
        }

    }

    @Override
    public Token loadJsonValue(String jsonValue) {
        return (Token) super.loadJsonValue(jsonValue);
    }

    @Override
    public Token loadSignature(String signature) {
        return (Token) super.loadSignature(signature);
    }

    public Token loadUserInfo(U user) {

        this.userInfo = user;
        return this;
    }

    public Token loadBusinessDescInfo(S businessDescInfo) {

        this.setBusinessDescInfo(businessDescInfo);
        return this;
    }

    public Token loadBiometricInfo(K biometricInfo) {

        this.biometricInfo = biometricInfo;
        return this;
    }

    public Token loadTokenModel(TokenModel tokenModel) {
        this.tokenModel = tokenModel;
        return this;
    }

}
