package com.trustkernel.uauth;

import com.trustkernel.uauth.model.*;
import com.trustkernel.uauth.tools.TSMAuthUtils;
import com.trustkernel.uauth.tools.UAuthTools;
import com.trustkernel.uauth.utils.CommonUtils;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import java.util.Optional;

/**
 * Created by watermelon on 2019/04/15
 */
public class UAuth<U, B> {
    private static final int DEFAULT_LENGTH = 32;

    private boolean tokenEnable = true;

    private boolean certEnable = true;

    private BusinessInfo<B> businessInfo;

    private UserInfo<U> userInfo;

    @Value("${uauth.tsm.url}")
    private String tsmUrl;

    @Value("${uauth.tsm.appId}")
    private String appId;

    @Value("${uauth.tsm.scret}")
    private String secret;

    private static Logger logger = LoggerFactory.getLogger(UAuth.class.getName());

    public String prepare() {
        return CommonUtils.random(DEFAULT_LENGTH);
    }

    public EnrollResult enroll(EnrollParameter enrollParameter, String privateKey) {

        /**
         * 步骤1:如果有agk，不带签名，非法agk，带签名，去tx验证agk的有效性
         * 步骤2:如果有bk，不带签名，非法bk,带签名，如果有agk，使用agk验证bk的有效性,如果没有有效agk，则此bk为非法bk
         * 步骤3:使用有效bk验证请求业务数据的有效性,无效不下发token
         * 步骤4:如果请求的业务数据有效，则下发token
         * 步骤4:如果存在有效agk，下发证书，如果存在有效bk下发证书
         */

        /**
         * 定义agk,bk的状态
         */
        boolean applicationGlobalPublicKeyStatus = false;//agk状态，存在的必要:agk为null时，为无效agk,但是无需抛异常
        boolean businessPublicKeyStatus = false;//bk状态

        /**
         * 从enrollParameter中解析数据
         */
        String applicationGlobalPublicKey = JsonUtils.fromJson(enrollParameter.getApplicationJsonValue(),
                EnrollParameter.Meta.class).getPub_key();
        String applicationJsonValue = enrollParameter.getApplicationJsonValue();
        String applicationGlobalPublicKeySignature = enrollParameter.getApplicationGlobalPublicKeySignature();
        String businessPublicKey = JsonUtils.fromJson(enrollParameter.getBusinessJsonValue(),
                EnrollParameter.Meta.class).getPub_key();
        String businessJsonValue = enrollParameter.getBusinessJsonValue();
        String businessPublicKeySignature = enrollParameter.getBusinessPublicKeySignature();
        EnrollParameter.BusinessMeta businessMeta = JsonUtils.fromJson(enrollParameter.getJsonValue(),
                EnrollParameter.BusinessMeta.class);

        EnrollResult<U, B> enrollResult = new EnrollResult<>();

        /**
         * 获取agk状态
         */
        if (StringUtils.isNotEmpty(applicationGlobalPublicKey)
                && StringUtils.isNotEmpty(applicationGlobalPublicKeySignature)) {
            if (TSMAuthUtils.verifyApplicationGlobalPublicKeyKey(applicationJsonValue, applicationGlobalPublicKeySignature, appId, secret)) {
                applicationGlobalPublicKeyStatus = true;
            } else {
                throw new RuntimeException("Failed to verify application global publicKey signature");
            }
        } else if (StringUtils.isNotEmpty(applicationGlobalPublicKey) && StringUtils.isEmpty(applicationGlobalPublicKeySignature)) {
            throw new RuntimeException("Illegal application global publicKey, because no corresponding signature was brought");
        }

        /**
         * 获取bk的状态
         */

        if (StringUtils.isNotEmpty(businessPublicKey) && StringUtils.isNotEmpty(businessPublicKeySignature)) {
            if (applicationGlobalPublicKeyStatus) {
                if (EncryptUtils.verify(applicationGlobalPublicKey, businessJsonValue, businessPublicKeySignature)) {
                    businessPublicKeyStatus = true;
                } else {
                    throw new RuntimeException("Failed to verify business publicKey signature");
                }
            } else {
                throw new RuntimeException("When verifying business public key signature, there is no valid application global publicKey");
            }
        } else if (StringUtils.isNotEmpty(businessPublicKey) && StringUtils.isEmpty(businessPublicKeySignature)) {
            throw new RuntimeException("Illegal business publicKey, because no corresponding signature was brought");
        }

        if (!(applicationGlobalPublicKeyStatus && businessPublicKeyStatus)) {
            /**
             * 没有agk又没有bk，既不能下发token,也不能下发证书，判定为异常数据
             */
            throw new RuntimeException("application global publicKey and business public key must have one");
        }

        /**
         * 使用有效bk验证业务请求数据签名的有效性，有效的话下发token,bk无效的话不下发token，因为可能无需下发token，只需下发agk的证书
         */

        if (businessPublicKeyStatus
                && EncryptUtils.verify(businessPublicKey, enrollParameter.getJsonValue(), enrollParameter.getSignature())) {
            Token token = UAuthTools
                    .toToken(userInfo.get(), businessInfo.get(), businessMeta.getUid(), businessMeta.getCpuId(), businessMeta.getFid(), privateKey);
            enrollResult.setToken(token);
        }

        /**
         * 下发agk证书
         */
        if (applicationGlobalPublicKeyStatus) {
            Cert.CertMeta certMeta = new Cert.CertMeta();

            Cert cert = UAuthTools.toCert(businessMeta, applicationGlobalPublicKey, privateKey);
            enrollResult.setApplicationGlobalKeyCert(cert);
        }
        /**
         * 下发bk证书
         */

        if (businessPublicKeyStatus) {
            Cert.CertMeta certMeta = new Cert.CertMeta();

            Cert cert = UAuthTools.toCert(businessMeta, businessPublicKey, privateKey);
            enrollResult.setBusinessCert(cert);
        }
        return enrollResult;
    }

    public boolean authenticate(AuthenticateParameter authenticateParameter,String publicKey) {
        /**
         * 验证token
         * 验证cert
         * 验证cert
         * 验证数据的准确性
         */
        if (!UAuthTools.verifyToken(authenticateParameter.getToken(), publicKey)) {
            logger.error("Failed to verify token");
            return false;
        }

        if (!UAuthTools.verifyCert(authenticateParameter.getApplicationCert(), publicKey)) {
            logger.error("Failed to verify applicationCert");
            return false;
        }

        if (!UAuthTools.verifyCert(authenticateParameter.getBusinessCert(), publicKey)) {
            logger.error("Failed to verify businessCert");
            return false;
        }

        if (!UAuthTools.compare(userInfo.get(), businessInfo.get(), authenticateParameter)) {
            logger.error("Failed to compare data");
            return false;
        }

        return true;
    }
}