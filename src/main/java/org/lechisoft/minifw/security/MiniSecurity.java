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
import org.apache.shiro.subject.Subject;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.UserModel;

public class MiniSecurity implements IMiniSecurity {
    Log log = null;
    
    public MiniSecurity() {
        this(ConstValue.DEFAULT_PATH);
    }

    public MiniSecurity(String path) {
        log = LogFactory.getLog(ConstValue.DEFAULT_LOGGER);
        
        HashedCredentialsMatcher hcm = new HashedCredentialsMatcher();
        hcm.setHashAlgorithmName(ConstValue.HASH_ALGORITHM_NAME);
        hcm.setHashIterations(1);
        
        XmlRealm xmlRealm = new XmlRealm(path);
        xmlRealm.setCredentialsMatcher(hcm);
        
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealms(Arrays.asList(xmlRealm));
        SecurityUtils.setSecurityManager(securityManager);
    }

    @Override
    public void login(String userName, String password) {
        
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(token);
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
        
        this.log.info(subject.getSession().getId());

    }

    @Override
    public void reload() {
        DefaultSecurityManager securityManager = (DefaultSecurityManager)SecurityUtils.getSecurityManager();
        XmlRealm xmlRealm = (XmlRealm)securityManager.getRealms().iterator().next();
        xmlRealm.load();
    }

    @Override
    public void addUser(UserModel user) {
        // TODO Auto-generated method stub
        
    }
}
