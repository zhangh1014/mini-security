package org.lechisoft.minifw.security;

import org.lechisoft.minifw.security.model.UserModel;

public interface IMiniSecurity {
    void login(String userName,String password);
    void logout();
    
    //void addUser(UserModel user);
}
