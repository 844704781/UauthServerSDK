package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.HttpUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by watermelon on 2019/04/10
 */
public class SoterAuth {
    private static final String baseURL = "https://api.weixin.qq.com/cgi-bin";

    @Data
    private class AccessToken {

        private String access_token;
        private Long expires_in;

    }

    /**
     * 用于申请accessToken
     *
     * @param appId
     * @param secret
     * @return
     */
    public String applyAccessToken(String appId, String secret) {
        if (StringUtils.isEmpty(appId)) {
            throw new RuntimeException("Invalid appId");
        }
        if (StringUtils.isEmpty(secret)) {
            throw new RuntimeException("Invalid secret");
        }

        String url = baseURL + "/token?grant_type=client_credential&appid=" + appId + "&secret=" + secret;
        return HttpUtils.get(url);
    }

    /**
     * 主要用于判断设备是否支持soter
     *
     * @param accessToken
     * @param model_key
     * @return
     */
    public boolean isSupported(String accessToken, String model_key) {

        if (StringUtils.isEmpty(accessToken)) {
            throw new RuntimeException("Invalid accessToken");
        }

        if (StringUtils.isEmpty(model_key)) {
            throw new RuntimeException("Invalid model_key");
        }

        String url = baseURL + "/soter_3rdapp/is_support?access_token=" + accessToken;
        Map<String, String> map = new HashMap<String, String>();
        map.put("model_key", model_key);
        return verify(url, map);
    }

    /**
     * 主要用于验证ASK公钥的合法性
     *
     * @param accessToken
     * @param ask_json
     * @param ask_json_signature
     * @return
     */
    public boolean verifyASKPublicKey(String accessToken, String ask_json, String ask_json_signature) {

        if (StringUtils.isEmpty(accessToken)) {
            throw new RuntimeException("Invalid accessToken");
        }

        String url = baseURL + "/soter_3rdapp/verify_ask?access_token=" + accessToken;
        Map<String, String> map = new HashMap<String, String>();
        map.put("ask_json", ask_json);
        map.put("ask_json_signature", ask_json_signature);
        return verify(url, map);
    }

    /**
     * 用于验证AuthKey的合法性
     *
     * @param jsonValue
     * @param signature
     * @param ask
     * @return
     */
    public static boolean verifyAuthPublicKey(String jsonValue, String signature, String ask) {

        if (StringUtils.isEmpty(jsonValue)) {
            throw new RuntimeException("Invalid original");
        }

        if (StringUtils.isEmpty(signature)) {
            throw new RuntimeException("Invalid signature");
        }

        if (StringUtils.isEmpty(ask)) {
            throw new RuntimeException("Invalid ask");
        }

        try {
            byte[] sign = EncryptUtils.base64Decode(signature);
            PublicKey publicKey = EncryptUtils.readPublicKey(ask);
            return EncryptUtils.verify(publicKey, jsonValue, sign);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to read pubKey");
        }
    }

    /**
     * 使用authKey验签
     *
     * @param jsonValue
     * @param signature
     * @param authKey
     * @return
     */
    public static boolean verify(String jsonValue, String signature, String authKey) {

        return EncryptUtils.verify(authKey, jsonValue, signature);
    }

    /**
     * 根据post请求结果验证true/false
     *
     * @param url
     * @param map
     * @return
     */
    private boolean verify(String url, Map<String, String> map) {

        String result = HttpUtils.post(url, map);
        JsonObject jsonObject = JsonUtils.fromJson(result, JsonObject.class);
        if (jsonObject.getErrcode().equals(0)) {
            return true;
        }
        return false;
    }

    /**
     * 腾讯服务器返回的数据格式
     *
     * @param <T>
     */
    @Data
    public class JsonObject<T> {

        private Integer errcode = 0;
        private String errmsg;
        private Boolean is_support;
        private Boolean is_verified;
        private String attk_version;
        private T object;

    }
}
