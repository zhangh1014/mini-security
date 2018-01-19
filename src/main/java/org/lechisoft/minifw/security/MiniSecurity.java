package org.lechisoft.minifw.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.ExpiredCredentialsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
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

    public void signin(String userName, String password, boolean rememberMe) throws Exception {
        Subject subject = this.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        token.setRememberMe(rememberMe);
        try {
            subject.login(token);
        } catch (UnknownAccountException e) {
            throw new Exception("unknown account.", e);
        } catch (LockedAccountException e) {
            throw new Exception("locked account.", e);
        } catch (DisabledAccountException e) {
            throw new Exception("disabled account.", e);
        } catch (IncorrectCredentialsException e) {
            throw new Exception("incorrect credentials.", e);
        } catch (ExpiredCredentialsException e) {
            throw new Exception("expired credentials.", e);
        } catch (ExcessiveAttemptsException e) {
            throw new Exception("excessive attempts.", e);
        } catch (AuthenticationException e) {
            throw new Exception("authentication faild.", e);
        } catch (Exception e) {
            throw new Exception("login faild.", e);
        } finally {
            // remove user
            if (!subject.isAuthenticated()) {
                this.getSession().removeAttribute(SESSION_LOGIN_OBJECT_KEY);
            }
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
    public void register(String userName, String password, String... roleNames) throws Exception {
        Subject subject = this.getSubject();
        if (subject.isAuthenticated()) {
            // no role
            if (roleNames.length == 0) {
                throw new Exception("unspecified role.");
            }

            // exists
            UserModel user = FileRealmDataProvider.loadUser(userName);
            if (null != user) {
                throw new Exception("user has already existed.");
            }

            String salt = String.valueOf((int) ((Math.random() * 9 + 1) * 100));
            Object simpleHash = new SimpleHash("MD5", password, salt, 1);

            user = new UserModel();
            user.setUserName(userName);
            user.setPassword(simpleHash.toString());
            user.setSalt(salt);
            for (String roleName : roleNames) {
                user.getRoles().add(roleName);
            }

            FileRealmDataProvider.addUser(user);
        }
    }

    @Override
    public void cancel(String userName) throws Exception {
        Subject subject = this.getSubject();
        if (subject.isAuthenticated()) {
            FileRealmDataProvider.removeUser(userName);
        }
    }
}
