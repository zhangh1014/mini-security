package org.lechisoft.minifw.security.exception;

public class UserAlreadyExistedException extends MiniSecurityException {
    private static final long serialVersionUID = 1L;

    public UserAlreadyExistedException() {
        super();
    }

    public UserAlreadyExistedException(String msg) {
        super(msg);
    }
}
