package org.lechisoft.minifw.security;

import org.lechisoft.minifw.security.exception.SecurityDataException;
import org.lechisoft.minifw.security.model.Role;
import org.lechisoft.minifw.security.model.User;

public interface SecurityData {
    User getUser(String userName) throws SecurityDataException;

    void register(String userName, String password, String salt, String... roleNames) throws SecurityDataException;

    void cancelUser(String userName) throws SecurityDataException;

    void changePassword(String userName, String password, String salt) throws SecurityDataException;

    Role getRole(String roleName) throws SecurityDataException;
}
