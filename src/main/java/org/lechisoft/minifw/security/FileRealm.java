package org.lechisoft.minifw.security;

import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.UserModel;

public class FileRealm extends AuthorizingRealm {
    public FileRealm() {
        HashedCredentialsMatcher hcm = new HashedCredentialsMatcher();
        hcm.setHashAlgorithmName(ConstValue.HASH_ALGORITHM_NAME);
        hcm.setHashIterations(1);
        this.setCredentialsMatcher(hcm);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String userName = (String) token.getPrincipal();

        // load user from authentication file
        UserModel user = FileRealmDataProvider.loadAuthenticationInfo(userName);
        if (null == user) {
            throw new UnknownAccountException(); // unknown account
        }
        // if has user,add to session
        this.setLoginUser(user);
        return new SimpleAuthenticationInfo(user.getUserName(), user.getPassword(),
                ByteSource.Util.bytes(user.getSalt()), this.getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();

        UserModel user = this.getLoginUser();
        for (String roleName : user.getRoles()) {
            authorizationInfo.addRole(roleName);

            List<String> permissions = FileRealmDataProvider.getPermissions(roleName);
            authorizationInfo.addStringPermissions(permissions);
        }
        return authorizationInfo;
    }

    private Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    private Session getSession() {
        return this.getSubject().getSession();
    }

    private UserModel getLoginUser() {
        return (UserModel) this.getSession().getAttribute(ConstValue.SESSION_LOGIN_OBJECT_KEY);
    }

    private void setLoginUser(UserModel user) {
        this.getSession().setAttribute(ConstValue.SESSION_LOGIN_OBJECT_KEY, user);
    }
}
