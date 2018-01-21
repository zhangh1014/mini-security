package org.lechisoft.minifw.security.exception;

public class IncorrectPasswordException extends MiniSecurityException {
    private static final long serialVersionUID = 1L;

    public IncorrectPasswordException() {
        super();
    }

    public IncorrectPasswordException(String msg) {
        super(msg);
    }
}
