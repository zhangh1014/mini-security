package org.lechisoft.minifw.security.exception;

public class UnAuthenticatedException extends MiniSecurityException {
    private static final long serialVersionUID = 1L;

    public UnAuthenticatedException() {
        super();
    }

    public UnAuthenticatedException(String msg) {
        super(msg);
    }
}
