package org.lechisoft.minifw.security.exception;

public class UserNotExistedException extends MiniSecurityException {
    private static final long serialVersionUID = 1L;

    public UserNotExistedException() {
        super();
    }

    public UserNotExistedException(String msg) {
        super(msg);
    }
}
