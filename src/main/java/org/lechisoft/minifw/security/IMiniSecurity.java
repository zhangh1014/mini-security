package org.lechisoft.minifw.security;

public interface IMiniSecurity {
    void reload();
    
    void login(String user,String pwd) throws Exception;
}
