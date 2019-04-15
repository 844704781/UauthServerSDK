package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.EncryptUtils;
import com.trustkernel.uauth.utils.JsonUtils;
import lombok.Data;
import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;

/**
 * Created by watermelon on 2019/04/12
 */
@RunWith(JUnit4.class)
public class IssuerTest {

    @Test
    public void test() throws Exception {
        Prepare prepare = prepare();

        /**
         * 服务器签发证书案例
         */
        Issuer.DeviceCSR deviceCSR = new Issuer.DeviceCSR();
        deviceCSR.setAuthPublicKey(prepare.getClientPrepare().getAuthPrivateKey());
        deviceCSR.setDeviceId("1231231241");
        Issuer.DeviceCert deviceCert = Issuer.sign(prepare.getServerPrepare().getSpPrivateKey(), deviceCSR);



        //---------------------------------------------------------------------------------------------------//
        Issuer.Params params = new Issuer.Params();
        params.setDeviceId("1231231241");
        params.setDeviceCert(deviceCert);
        Issuer.RequestParams requestParams=new Issuer.RequestParams();
        String jsonValue=JsonUtils.toJson(params, Issuer.Params.class);
        requestParams.setJsonValue(jsonValue);
        requestParams.setSignature(EncryptUtils.base64Encode(EncryptUtils.sign(jsonValue,prepare.getClientPrepare().getAuthPrivateKey())));
        //---------------------------------------------------------------------------------------------------//

        /**
         * 服务器验证
         */

        boolean v1=Issuer.verify(prepare.getServerPrepare().getSpPubilcKey(),requestParams);
        Assert.assertEquals(true,v1);

    }

























    public static Prepare prepare() throws Exception {
        //业务公钥
        String auth_publicKey_path = "/home/watermelon/keypair/lib/pub01.pem";
        File file = FileUtils.getFile(auth_publicKey_path);
        String auth_publicKey = FileUtils.readFileToString(file, "UTF-8");
        EncryptUtils.readPublicKey(auth_publicKey);

        //业务私钥
        String auth_privateKey_path = "/home/watermelon/keypair/lib/pri01.pem";
        File auth_privateKey_file = FileUtils.getFile(auth_privateKey_path);
        String auth_privateKey = FileUtils.readFileToString(auth_privateKey_file, "UTF-8");
        EncryptUtils.readPrivateKey(auth_privateKey);

        //SP私钥
        String sp_privateKey_path = "/home/watermelon/keypair/lib/pri02.pem";
        File sp_privateKey_file = FileUtils.getFile(sp_privateKey_path);
        String sp_privateKey = FileUtils.readFileToString(sp_privateKey_file, "UTF-8");
        EncryptUtils.readPrivateKey(sp_privateKey);

        //SP公钥
        String sp_publicKey_path = "/home/watermelon/keypair/lib/pub02.pem";
        File sp_publicKey_file = FileUtils.getFile(sp_publicKey_path);
        String sp_publicKey = FileUtils.readFileToString(sp_publicKey_file, "UTF-8");
        EncryptUtils.readPublicKey(sp_publicKey);

        return new Prepare(new ServerPrepare(auth_publicKey, sp_publicKey, sp_privateKey), new ClientPrepare(auth_privateKey));

    }

    @Data
    public static class ServerPrepare {
        private String authPublicKey;
        private String spPubilcKey;
        private String spPrivateKey;

        public ServerPrepare(String authPublicKey, String spPubilcKey, String spPrivateKey) {
            this.authPublicKey = authPublicKey;
            this.spPubilcKey = spPubilcKey;
            this.spPrivateKey = spPrivateKey;
        }
    }

    @Data
    public static class ClientPrepare {
        private String authPrivateKey;

        public ClientPrepare(String authPrivateKey) {
            this.authPrivateKey = authPrivateKey;
        }
    }

    @Data
    public static class Prepare {
        private ServerPrepare serverPrepare;
        private ClientPrepare clientPrepare;

        public Prepare(ServerPrepare serverPrepare, ClientPrepare clientPrepare) {
            this.serverPrepare = serverPrepare;
            this.clientPrepare = clientPrepare;
        }
    }
}
