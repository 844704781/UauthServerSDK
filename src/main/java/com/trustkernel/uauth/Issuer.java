package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import lombok.Data;


/**
 * Created by watermelon on 2019/04/10
 */
public class Issuer{

    @Data
    public static class DeviceCSR{
        private String deviceId;
        private String authPublicKey;


    }

    @Data
    public static class DeviceCert{
        private String jsonValue;
        private String signature;

        public DeviceCert(String jsonValue, String signature) {
            this.jsonValue = jsonValue;
            this.signature = signature;
        }
    }

    @Data
    public static class RequestParams{
        private String jsonValue;
        private String signature;
    }

    @Data
    public static class Params{
        private String deviceId;
        private DeviceCert deviceCert;
    }

    public static DeviceCert sign(String privateKey, DeviceCSR deviceCSR) {
        String jsonValue= JsonUtils.toJson(deviceCSR,deviceCSR.getClass());
        String signature= EncryptUtils.base64Encode(EncryptUtils.sign(jsonValue,privateKey));
        return new DeviceCert(jsonValue,signature);
    }

    public static boolean verify(String publicKey, RequestParams requestParams) {
        Params params = JsonUtils.fromJson(requestParams.getJsonValue(), Params.class);
        DeviceCert deviceCert = params.getDeviceCert();
        boolean f1 = EncryptUtils.verify(publicKey, deviceCert.getJsonValue(), deviceCert.getSignature());

        DeviceCSR deviceCSR = JsonUtils.fromJson(deviceCert.getJsonValue(), DeviceCSR.class);
        boolean f2 = EncryptUtils.verify(deviceCSR.getAuthPublicKey(), requestParams.getJsonValue(), requestParams.getSignature());

        boolean f3 = deviceCSR.getDeviceId().equals(params.getDeviceId());
        return f1 && f2 && f3;
    }

}
