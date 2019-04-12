package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;

import java.nio.charset.Charset;
import java.util.LinkedHashMap;

/**
 * Created by watermelon on 2019/04/10
 */
public class Issuer<T> extends Base<T> {

    /**
     * 一般指代deviceId，也可以是用户业务需要签的数据
     */

    /**
     * 签发的证书对象
     */
    private Certificate certificate;

    public static class Certificate extends Model {
    }

    @Override
    public Issuer loadPrivateKey(String pri) {
        return (Issuer) super.loadPrivateKey(pri);
    }

    @Override
    public Issuer loadPublicKey(String pub) {
        return (Issuer) super.loadPublicKey(pub);
    }

    /**
     * 签名
     *
     * @return
     */
    @Override
    public Certificate build() {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        /**
         * AuthKey
         */
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\n");
        sb.append(EncryptUtils.base64Encode(this.getPublicKey().getEncoded()));
        sb.append("-----END PUBLIC KEY-----\n");
        map.put("publicKey", sb.toString());
        /**
         * deviceId
         */
        String jsonValue = JsonUtils.toJson(this.getBusinessDescInfo(), this.getBusinessDescInfo().getClass());
        map.put("data", jsonValue);
        this.certificate = new Certificate();

        this.certificate.setJsonValue(JsonUtils.toJson(map, map.getClass()));
        byte[] bytes = this.certificate.getJsonValue().getBytes(Charset.forName("UTF-8"));
        this.certificate.setSignature(EncryptUtils.base64Encode(EncryptUtils.sign(bytes, this.getPrivateKey())));
        return this.certificate;
    }

    @Override
    public boolean verify() {
        /**
         * 验证证书是否合法
         */
        if (this.certificate != null) {
            return EncryptUtils.verify(this.getPublicKey(), this.certificate.getJsonValue(), this.certificate.getSignature());
        } else {
            /**
             * 验证业务信息是否合法,传入的jsonValue字符串
             */
            return EncryptUtils.verify(this.getPublicKey(), this.getJsonValue(), this.getSignature()) && this.getValidator().verify();
        }

    }

    @Override
    public Issuer registerValidator(Validator validator) {
        return (Issuer) super.registerValidator(validator);
    }

    @Override
    public Issuer loadJsonValue(String jsonValue) {
        return (Issuer) super.loadJsonValue(jsonValue);
    }

    @Override
    public Issuer loadSignature(String signature) {
        return (Issuer) super.loadSignature(signature);
    }

    public Issuer loadCertificate(Certificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public Issuer loadBusinessDescInfo(T t) {
        this.setBusinessDescInfo(t);
        return this;
    }

}
