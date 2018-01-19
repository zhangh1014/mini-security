package org.lechisoft.minifw.security;

import java.util.List;

public interface IMiniSecurity {
    void signin(String userName, String password) throws Exception;

    void signin(String userName, String password, boolean rememberMe) throws Exception;

    void signout();

    void register(String userName, String password, String... roleNames) throws Exception;
    
    void cancel(String userName) throws Exception;

    boolean isPermitted(String permission);

    boolean isPermittedAll(String... permissions);

    boolean isPermittedAny(String... permissions);

    boolean hasRole(String roleName);

    boolean hasAllRoles(String... roles);

    boolean hasAnyRole(String... roles);

    List<String> getTagRoles(String tag);

}
