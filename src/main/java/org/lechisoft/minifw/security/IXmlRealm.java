package org.lechisoft.minifw.security;

import org.lechisoft.minifw.security.model.UserModel;

public interface IXmlRealm {
    public void load();
    
    public void addUser(UserModel user);
}
