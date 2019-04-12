package com.trustkernel.uauth;

import com.google.gson.Gson;
import com.trustkernel.uauth.utils.JsonUtils;

/**
 * Created by watermelon on 2019/04/11
 */
public class Test {

    public static void main(String[] args) {
        Integer a = 1;

        String v = JsonUtils.toJson(a, a.getClass());
        System.out.println(v);
    }
}
