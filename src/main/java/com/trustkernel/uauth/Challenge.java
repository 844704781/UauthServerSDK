package com.trustkernel.uauth;

import com.trustkernel.uauth.utils.CommonUtils;

/**
 * Created by watermelon on 2019/04/10
 */
public class Challenge {

    private static final int DEFAULT_LENGTH = 32;

    public static String generateNonce() {
        return CommonUtils.random(DEFAULT_LENGTH);
    }
}
