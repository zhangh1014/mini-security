package org.lechisoft.minifw.security.exception;

public class PasswordNotChangedException extends MiniSecurityException {
    private static final long serialVersionUID = 1L;

    public PasswordNotChangedException() {
        super();
    }

    public PasswordNotChangedException(String msg) {
        super(msg);
    }
}
