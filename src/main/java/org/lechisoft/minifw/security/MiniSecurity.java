package org.lechisoft.minifw.security;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.ExpiredCredentialsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.PermissionModel;
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class MiniSecurity implements IMiniSecurity {

    
    private String configFilePath = "";

    Log log = null;

    
    // private List<UserModel> users = null;

    public MiniSecurity() {
        this(ConstValue.DEFAULT_PATH);
    }

    public MiniSecurity(String path) {
        log = LogFactory.getLog(ConstValue.DEFAULT_LOGGER);
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealms(Arrays.asList(new XmlRealm(path)));
        SecurityUtils.setSecurityManager(securityManager);

        
    }

    

    

    

    

//    private RoleModel getRole(String roleId) {
//        for (RoleModel role : this.roles) {
//            if (roleId.equals(role.getRoleId())) {
//                return role;
//            }
//        }
//        return null;
//    }
//
//    
//
//    public void reload() {
//        this.load();
//    }

    @Override
    public void login(String userName, String password) {
        // if("".equals(userName.trim())){
        // throw new Exception("error user name.");
        // }
        //
        // if("".equals(password.trim())){
        // throw new Exception("error password.");
        // }
        //
        // UserModel user = this.getUser(userName);
        // if(null == user){
        // throw new Exception("no user.");
        // }
        //
        // String userPwd = MD5Util.getMD5(password, user.getSalt());
        // if(!userPwd.equals(user.getUserPwd())){
        // throw new Exception("incorrect password.");
        // }
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
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
        } catch (Exception e) {
            this.log.info("login faild.", e);
        }
        
        this.log.info(subject.getSession().getId());

    }

    @Override
    public void reload() {
        // TODO Auto-generated method stub
        
    }
}
