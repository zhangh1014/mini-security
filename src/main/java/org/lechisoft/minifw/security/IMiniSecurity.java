package org.lechisoft.minifw.security;

import org.lechisoft.minifw.security.model.UserModel;

public interface IMiniSecurity {
    void reload();
    
    void login(String userName,String password);
    
    void addUser(UserModel user);
}
