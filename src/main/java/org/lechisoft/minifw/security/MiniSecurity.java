package org.lechisoft.minifw.security;

import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.ExpiredCredentialsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.UserModel;

public class MiniSecurity implements IMiniSecurity {
    Log log;
    Subject subject;

    public MiniSecurity() {
        this(new XmlRealm());
    }

    public MiniSecurity(AuthorizingRealm realm) {
        this.log = LogFactory.getLog(ConstValue.DEFAULT_LOGGER);

        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealms(Arrays.asList(realm));
        SecurityUtils.setSecurityManager(securityManager);
        this.subject = SecurityUtils.getSubject();
    }

    @Override
    public void login(String userName, String password) {
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        try {
            this.subject.login(token);
        } catch (UnknownAccountException e) {
            this.log.info("unknown account.");
        } catch (LockedAccountException e) {
            this.log.info("locked account.");
        } catch (DisabledAccountException e) {
            this.log.info("disabled account.");
        } catch (IncorrectCredentialsException e) {
            this.log.info("incorrect credentials.");
        } catch (ExpiredCredentialsException e) {
            this.log.info("expired credentials.");
        } catch (ExcessiveAttemptsException e) {
            this.log.info("excessive attempts.");
        } catch (AuthenticationException e) {
            this.log.info("authentication faild.");
        } catch (Exception e) {
            this.log.info("login faild.", e);
        }

    }

    @Override
    public void logout() {
        this.subject.logout();
    }
}
