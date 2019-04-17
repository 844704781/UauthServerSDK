package com.trustkernel.uauth.tools;

import com.trustkernel.uauth.model.*;
import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * Created by watermelon on 2019/04/15
 */
public class UAuthTools {
    public static final Integer SOTER = 1;
    public static final Integer PIN = 2;

    private static Cert.CertMeta prepareJsonMap(EnrollParameter.BusinessMeta meta) {
        Cert.CertMeta certMeta = new Cert.CertMeta();
        if (recognizeType(meta).equals(UAuthTools.SOTER)) {
            certMeta.setType(UAuthTools.SOTER);
            certMeta.setFid(meta.getFid());
            certMeta.setFp_n(meta.getFp_n());
            certMeta.setFp_v(meta.getFp_v());
        } else if (recognizeType(meta).equals(UAuthTools.PIN)) {
            certMeta.setType(UAuthTools.PIN);
        }
        certMeta.setTee_n(meta.getTee_n());
        certMeta.setTee_v(meta.getTee_v());
        certMeta.setUid(meta.getUid());
        certMeta.setDeviceId(meta.getCpuId());
        return certMeta;
    }

    /**
     * 识别数据是PIN码还是soter
     *
     * @param meta
     * @return
     */
    public static Integer recognizeType(EnrollParameter.BusinessMeta meta) {
        if (StringUtils.isEmpty(meta.getFid())
                && StringUtils.isEmpty(meta.getFp_n())
                && StringUtils.isEmpty(meta.getFp_v())
                && StringUtils.isNotEmpty(meta.getCpuId())
                && StringUtils.isNotEmpty(meta.getTee_n())
                && StringUtils.isNotEmpty(meta.getTee_v())
                && StringUtils.isNotEmpty(meta.getUid())) {
            return PIN;
        }
        return SOTER;
    }

    /**
     * 生成证书,将公钥存于设备
     *
     * @param businessMeta
     * @param publicKey
     * @param privateKey
     * @return
     */
    public static Cert toCert(EnrollParameter.BusinessMeta businessMeta, String publicKey, String privateKey) {
        Cert.CertMeta certMeta = prepareJsonMap(businessMeta);
        certMeta.setPublicKey(publicKey);
        String jsonValue = JsonUtils.toJson(certMeta, certMeta.getClass());
        String signature = EncryptUtils.base64Encode(EncryptUtils.sign(jsonValue, privateKey));
        return new Cert(jsonValue, signature);
    }

    /**
     * 生成token
     *
     * @param u
     * @param b
     * @param uid
     * @param cpuId
     * @param fid
     * @param privateKey
     * @param <U>
     * @param <B>
     * @return
     */
    public static <U, B> Token toToken(U u, B b, String uid, String cpuId, String fid, String privateKey) {
        Token.TokenMeta<U, B> tokenMeta = new Token.TokenMeta<>();
        tokenMeta.setUserInfo(u);

        Token.BusinessDescriptionInformation<B> businessDescricptionInformation = new Token.BusinessDescriptionInformation<>();
        businessDescricptionInformation.setScene(b);
        businessDescricptionInformation.setUid(uid);
        tokenMeta.setBusinessDescriptionInformation(businessDescricptionInformation);
        Token.BiometricInformation biometricInformation = new Token.BiometricInformation();
        biometricInformation.setCpuId(cpuId);
        biometricInformation.setFid(fid);
        tokenMeta.setBiometricInformation(biometricInformation);

        Token token = new Token();
        token.setJsonValue(JsonUtils.toJson(token, token.getClass()));
        token.setSignature(EncryptUtils.base64Encode(EncryptUtils.sign(token.getJsonValue(), privateKey)));
        return token;
    }

    /**
     * 验证token中的签名
     *
     * @param token
     * @param publicKey
     * @return
     */
    public static boolean verifyToken(Token token, String publicKey) {
        return EncryptUtils.verify(publicKey, token.getJsonValue(), token.getJsonValue());
    }

    /**
     * 验证证书中的签名
     *
     * @param cert
     * @param publicKey
     * @return
     */
    public static boolean verifyCert(Cert cert, String publicKey) {
        return EncryptUtils.verify(publicKey, cert.getJsonValue(), cert.getJsonValue());
    }

    /**
     * 对比证书以及token中的设备信息与业务数据的设备信息是否一致
     *
     * @param u
     * @param b
     * @param authenticateParameter
     * @param <U>
     * @param <B>
     * @return
     */
    public static <U, B> boolean compare(U u, B b, AuthenticateParameter authenticateParameter) {
        String userInfo = JsonUtils.toJson(u, u.getClass());
        String business = JsonUtils.toJson(b, b.getClass());
        Cert.CertMeta businessCert = JsonUtils.fromJson(authenticateParameter.getBusinessCert().getJsonValue(), Cert.CertMeta.class);
        Cert.CertMeta applicationCert = JsonUtils.fromJson(authenticateParameter.getApplicationCert().getJsonValue(), Cert.CertMeta.class);
        Token.TokenMeta<U, B> token = JsonUtils.fromJson(authenticateParameter.getToken().getJsonValue(), Token.TokenMeta.class);

        if (!compareToken(token, userInfo, business, authenticateParameter.getCpuId(), authenticateParameter.getFid(), u.getClass(), b.getClass())) {
            return false;
        }

        if (!compareCert(businessCert, authenticateParameter.getCpuId(), authenticateParameter.getFid())) {
            return false;
        }

        if (!compareCert(applicationCert, authenticateParameter.getCpuId(), authenticateParameter.getFid())) {
            return false;
        }
        return true;
    }

    /**
     * 对比证书中的设备信息与业务数据中的设备信息是否一致
     *
     * @param businessCert
     * @param cpuId
     * @param fid
     * @return
     */
    private static boolean compareCert(Cert.CertMeta businessCert, String cpuId, String fid) {
        if (businessCert.getDeviceId().equals(cpuId) && businessCert.getFid().equals(fid))
            return true;
        return false;
    }

    /**
     * 对比token中的设备信息与业务数据中的设备信息是否一致
     *
     * @param token
     * @param userInfo
     * @param business
     * @param cpuId
     * @param fid
     * @param uclz
     * @param bclz
     * @return
     */
    public static boolean compareToken(Token.TokenMeta token, String userInfo, String business, String cpuId, String fid, Class uclz, Class bclz) {
        String _userInfo = JsonUtils.toJson(token.getUserInfo(), uclz);
        String _business = JsonUtils.toJson(token.getBusinessDescriptionInformation(), bclz);
        Token.BiometricInformation biometricInformation = token.getBiometricInformation();
        if (_userInfo.equals(userInfo) && _business.equals(business) && biometricInformation.getCpuId().equals(cpuId) && biometricInformation.getFid()
                .equals(fid))
            return true;
        return false;
    }

}
