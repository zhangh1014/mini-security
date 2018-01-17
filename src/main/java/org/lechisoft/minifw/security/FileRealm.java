package org.lechisoft.minifw.security;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.PermissionModel;
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class FileRealm extends AuthorizingRealm {
    private String configFilePath = "";
    Log log = null;

    // 权限、角色、用户
    private List<PermissionModel> permissions = null;
    private List<RoleModel> roles = null;

    public FileRealm() {
        log = LogFactory.getLog(ConstValue.DEFAULT_LOGGER);

        // URL url =
        // this.getClass().getClassLoader().getResource(ConstValue.AUTHENTICATION_INFO);
        // if (null == url) {
        // this.log.error("can not find authentication info:classpath/" +
        // ConstValue.AUTHENTICATION_INFO);
        // return;
        // }
        // url =
        // this.getClass().getClassLoader().getResource(ConstValue.AUTHORIZATION_INFO);
        // if (null == url) {
        // this.log.error("can not find authorization info:classpath/" +
        // ConstValue.AUTHORIZATION_INFO);
        // return;
        // }
        // this.configFilePath = url.getPath();

        HashedCredentialsMatcher hcm = new HashedCredentialsMatcher();
        hcm.setHashAlgorithmName(ConstValue.HASH_ALGORITHM_NAME);
        hcm.setHashIterations(1);
        this.setCredentialsMatcher(hcm);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // get user id from token
        String userName = (String) token.getPrincipal();

        // load user by user id
        UserModel user = this.loadUser(userName);
        if (null == user) {
            throw new UnknownAccountException(); // unknown account
        }

        return new SimpleAuthenticationInfo(user.getUserName(), user.getPassword(),
                ByteSource.Util.bytes(user.getSalt()), this.getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {
        String lala = "fdasfas";
        lala += "a";
        // TODO Auto-generated method stub
        return null;
    }

    private UserModel loadUser(String userName) {
        URL url = this.getClass().getClassLoader().getResource(ConstValue.AUTHENTICATION_INFO);
        File file = new File(url.getPath());
        LineIterator li = null;
        try {
            li = FileUtils.lineIterator(file, "UTF-8");
            while (li.hasNext()) {
                String line = li.nextLine();

                String pattern = "^" + userName + "=(.+?),(.+)$";
                Pattern r = Pattern.compile(pattern);
                Matcher m = r.matcher(line);
                if (m.find()) {
                    UserModel user = new UserModel(userName);

                    String password = m.group(1);
                    String salt = "";
                    if (password.indexOf(":") != -1) {
                        salt = password.split(":")[1];
                        password = password.split(":")[0];
                    }
                    user.setPassword(password);
                    user.setSalt(salt);

                    String roles = m.group(2);
                    if (roles.indexOf(",") != -1) {
                        for (String role : roles.split(",")) {
                            user.getRoles().add(role);
                        }
                    }
                    return user;
                }
            }
            return null;
        } catch (IOException e) {
            this.log.error("can not find authentication file:classpath/" + ConstValue.AUTHENTICATION_INFO);
            return null;
        } finally {
            try {
                li.close();
            } catch (IOException e) {
                this.log.error("close authentication file IOException.");
            }
        }
    }

}
