package org.lechisoft.minifw.security;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.lechisoft.minifw.security.exception.SecurityDataException;
import org.lechisoft.minifw.security.model.Role;
import org.lechisoft.minifw.security.model.User;

public class MiniRealm extends AuthorizingRealm {

    SecurityData data = null;

    public MiniRealm(SecurityData data) {
        this.data = data;

        HashedCredentialsMatcher hcm = new HashedCredentialsMatcher();
        hcm.setHashAlgorithmName("MD5");
        hcm.setHashIterations(1);
        this.setCredentialsMatcher(hcm);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String userName = (String) token.getPrincipal();

        User user;
        try {
            user = this.data.getUser(userName);
        } catch (SecurityDataException e) {
            throw new UnknownAccountException();
        }
        if (null == user) {
            throw new UnknownAccountException();
        }

        return new SimpleAuthenticationInfo(user.getUserName(), user.getPassword(),
                ByteSource.Util.bytes(user.getSalt()), this.getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String userName = (String) principals.getPrimaryPrincipal();

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        try {
            User user = this.data.getUser(userName);
            if (null == user) {
                throw new UnknownAccountException();
            }

            for (String roleName : user.getRoles()) {
                authorizationInfo.addRole(roleName);

                Role role = this.data.getRole(roleName);
                authorizationInfo.addStringPermissions(role.getPermissions());
            }
        } catch (SecurityDataException e1) {
            throw new UnknownAccountException();
        }
        return authorizationInfo;
    }
}
