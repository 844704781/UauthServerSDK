package com.trustkernel.uauth.utils;

import com.google.gson.*;
import jdk.nashorn.internal.parser.JSONParser;
import org.apache.commons.lang3.StringUtils;

public class JsonUtils {

    private static Gson gson = new GsonBuilder().create();

    public static String toJson(Object object, Class cls) {
        return gson.toJson(object, cls);
    }

    public static <T> T fromJson(String json, Class<T> beanClass) {
        return gson.fromJson(json, beanClass);
    }

}
