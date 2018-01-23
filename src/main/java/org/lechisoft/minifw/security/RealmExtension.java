package org.lechisoft.minifw.security;

import org.lechisoft.minifw.security.exception.MiniSecurityException;

public interface RealmExtension {
    void addUser(String userName, String password, String salt, String... roleNames) throws MiniSecurityException;
    void removeUser(String userName) throws MiniSecurityException;
    void changePassword(String userName, String password, String salt) throws MiniSecurityException;
}
