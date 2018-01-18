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
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.lechisoft.minifw.log.MiniLog;
import org.lechisoft.minifw.security.common.ConstValue;

public class MiniSecurity {

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

    public void login(String userName, String password) {
        this.login(userName, password, false);
    }

    public void login(String userName, String password, boolean rememberMe) {
        Subject subject = this.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        token.setRememberMe(rememberMe);
        try {
            // login
            subject.login(token);
        } catch (UnknownAccountException e) {
            MiniLog.info("unknown account.");
        } catch (LockedAccountException e) {
            MiniLog.info("locked account.");
        } catch (DisabledAccountException e) {
            MiniLog.info("disabled account.");
        } catch (IncorrectCredentialsException e) {
            MiniLog.info("incorrect credentials.");
        } catch (ExpiredCredentialsException e) {
            MiniLog.info("expired credentials.");
        } catch (ExcessiveAttemptsException e) {
            MiniLog.info("excessive attempts.");
        } catch (AuthenticationException e) {
            MiniLog.info("authentication faild.");
        } catch (Exception e) {
            MiniLog.info("login faild.", e);
        } finally {
            // remove user
            if (!subject.isAuthenticated()) {
                this.getSession().setAttribute(ConstValue.SESSION_LOGIN_OBJECT_KEY, null);
            }
        }
    }

    public void logout() {
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

    public boolean hasRole(String role) {
        Subject subject = this.getSubject();
        return subject.hasRole(role);
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
        return FileRealmDataProvider.getTagRoles(tag);
    }
}
