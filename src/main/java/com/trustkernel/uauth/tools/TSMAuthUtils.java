package com.trustkernel.uauth.tools;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.HttpUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by watermelon on 2019/04/16
 */
public class TSMAuthUtils {

    private static final String baseURL = "https://api.weixin.qq.com/cgi-bin";

    @Data
    private static class AccessToken {
        private Integer errcode = 0;
        private String errmsg;
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
    private static String applyAccessToken(String appId, String secret) {
        if (StringUtils.isEmpty(appId)) {
            throw new RuntimeException("Invalid appId");
        }
        if (StringUtils.isEmpty(secret)) {
            throw new RuntimeException("Invalid secret");
        }

        String url = baseURL + "/token?grant_type=client_credential&appid=" + appId + "&secret=" + secret;
        AccessToken accessToken = JsonUtils.fromJson(HttpUtils.get(url), AccessToken.class);
        if (!accessToken.getErrcode().equals(0)) {
            throw new RuntimeException(accessToken.getErrmsg());
        }
        return accessToken.getAccess_token();
    }

    /**
     * 主要用于验证ASK公钥的合法性
     *
     * @param accessToken
     * @param ask_json
     * @param ask_json_signature
     * @return
     */
    private static boolean verifyASKPublicKey(String accessToken, String ask_json, String ask_json_signature) {

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
     * 根据post请求结果验证true/false
     *
     * @param url
     * @param map
     * @return
     */
    private static boolean verify(String url, Map<String, String> map) {

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
    private static class JsonObject<T> {

        private Integer errcode = 0;
        private String errmsg;
        private Boolean is_support;
        private Boolean is_verified;
        private String attk_version;
        private T object;

    }

    /**
     * 主要用于判断设备是否支持soter
     *
     * @param accessToken
     * @param model_key
     * @return
     */
    public static boolean isSupported(String accessToken, String model_key) {

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

    public static boolean verifyApplicationGlobalPublicKeyKey(String jsonValue, String signature, String appId, String secret) {
        String accessToken =applyAccessToken(appId,secret);
        return verifyASKPublicKey(accessToken,jsonValue,signature);
    }
}
