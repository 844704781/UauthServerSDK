package com.trustkernel.uauth.exception;

/**
 * Created by watermelon on 2019/04/15
 */
public class UAuthException extends RuntimeException{
    static final long serialVersionUID = -7034897190745766939L;

    public UAuthException() {
    }

    public UAuthException(String s) {
        super(s);
    }

    public UAuthException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public UAuthException(Throwable throwable) {
        super(throwable);
    }

    public UAuthException(String s, Throwable throwable, boolean b, boolean b1) {
        super(s, throwable, b, b1);
    }
}
