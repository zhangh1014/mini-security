package org.lechisoft.minifw.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.lechisoft.minifw.security.model.UserModel;

public class MiniSecurity implements IMiniSecurity {
    public final static String SESSION_LOGIN_OBJECT_KEY = "loginObject";

    public MiniSecurity() {
        this(new FileRealm());
    }

    public MiniSecurity(AuthorizingRealm realm) {
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealms(Arrays.asList(realm));
        SecurityUtils.setSecurityManager(securityManager);
    }

    public Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    public Session getSession() {
        return this.getSubject().getSession();
    }

    public void signin(String userName, String password) throws Exception {
        this.signin(userName, password, false);
    }

    public void signin(String userName, String password, boolean rememberMe) throws AuthenticationException {
        Subject subject = this.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        token.setRememberMe(rememberMe);
        subject.login(token);
        
        // check
        if (!subject.isAuthenticated()) {
            this.getSession().removeAttribute(SESSION_LOGIN_OBJECT_KEY);
        }
    }

    public void signout() {
        Subject subject = this.getSubject();
        subject.logout();
    }

    public boolean isPermitted(String permission) {
        Subject subject = this.getSubject();
        return subject.isPermitted(permission);
    }

    public boolean isPermittedAll(String... permissions) {
        Subject subject = this.getSubject();
        return subject.isPermittedAll(permissions);
    }

    public boolean isPermittedAny(String... permissions) {
        Subject subject = this.getSubject();
        for (String permission : permissions) {
            if (subject.isPermitted(permission)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasRole(String roleName) {
        Subject subject = this.getSubject();
        return subject.hasRole(roleName);
    }

    public boolean hasAllRoles(String... roles) {
        List<String> lst = new ArrayList<String>();
        for (String role : roles) {
            lst.add(role);
        }
        Subject subject = this.getSubject();
        return subject.hasAllRoles(lst);
    }

    public boolean hasAnyRole(String... roles) {
        Subject subject = this.getSubject();
        for (String role : roles) {
            if (subject.hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    public List<String> getTagRoles(String tag) {
        Subject subject = this.getSubject();
        if (subject.isAuthenticated()) {
            return FileRealmDataProvider.getTagRoles(tag);
        }
        return new ArrayList<String>();
    }

    @Override
    public void register(String userName, String password, String... roleNames) throws IOException {
        Subject subject = this.getSubject();
        if (subject.isAuthenticated()) {
            // no role
            if (roleNames.length == 0) {
                //throw new Exception("unspecified role.");
            }

            // exists
            UserModel user = FileRealmDataProvider.loadUser(userName);
            if (null != user) {
                //throw new Exception("user has already existed.");
            }

            String salt = String.valueOf((int) ((Math.random() * 9 + 1) * 100));
            Object simpleHash = new SimpleHash("MD5", password, salt, 1);

            FileRealmDataProvider.addUser(userName, simpleHash.toString(), salt, roleNames);
        }
    }

    @Override
    public void cancel(String userName) throws Exception {
        Subject subject = this.getSubject();
        if (subject.isAuthenticated()) {

            // exists
            UserModel user = FileRealmDataProvider.loadUser(userName);
            if (null == user) {
                throw new Exception("user not existed.");
            }

            FileRealmDataProvider.removeUser(userName);
        }
    }

    @Override
    public void changePassword(String userName, String password) throws Exception {
        Subject subject = this.getSubject();
        if (subject.isAuthenticated()) {

            // exists
            UserModel user = FileRealmDataProvider.loadUser(userName);
            if (null == user) {
                throw new Exception("user not existed.");
            }

            String salt = String.valueOf((int) ((Math.random() * 9 + 1) * 100));
            Object simpleHash = new SimpleHash("MD5", password, salt, 1);

            FileRealmDataProvider.changePassword(userName, simpleHash.toString(), salt);
        }
    }
}
