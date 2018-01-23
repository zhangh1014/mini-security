package org.lechisoft.minifw.security;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.lechisoft.minifw.security.exception.IncorrectPasswordException;
import org.lechisoft.minifw.security.exception.MiniSecurityException;
import org.lechisoft.minifw.security.exception.PasswordNotChangedException;
import org.lechisoft.minifw.security.exception.UnAuthenticatedException;
import org.lechisoft.minifw.security.exception.UserAlreadyExistedException;
import org.lechisoft.minifw.security.exception.UserNotExistedException;
import org.lechisoft.minifw.security.model.User;

public class MiniSecurity {

    private List<RealmExtension> realmExtensions;
    
    public MiniSecurity(AuthorizingRealm... realms) {
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealms(Arrays.asList(realms));
        SecurityUtils.setSecurityManager(securityManager);
    }

    public List<RealmExtension> getRealmExtensions() {
        return realmExtensions;
    }

    public void setRealmExtensions(List<RealmExtension> realmExtensions) {
        this.realmExtensions = realmExtensions;
    }

    private Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    public Session getSession() {
        return SecurityUtils.getSubject().getSession();
    }

    public void signin(String userName, String password)
            throws UserNotExistedException, IncorrectPasswordException, MiniSecurityException {
        this.signin(userName, password, false);
    }

    public void signin(String userName, String password, boolean rememberMe)
            throws UserNotExistedException, IncorrectPasswordException, MiniSecurityException {
        
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        token.setRememberMe(rememberMe);
        
        Subject subject = this.getSubject();
        try {
            subject.login(token);
        } catch (UnknownAccountException e) {
            throw new UserNotExistedException("the user does not exist.");
        } catch (IncorrectCredentialsException e) {
            throw new IncorrectPasswordException("incorrect password.");
        } catch (AuthenticationException e) {
            throw new MiniSecurityException(e.getMessage());
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

    public boolean hasRole(String role) {
        Subject subject = this.getSubject();
        return subject.hasRole(role);
    }

    public boolean hasAllRoles(String... roles) {
        Subject subject = this.getSubject();
        return subject.hasAllRoles(Arrays.asList(roles));
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

//    @Override
//    public void register(String userName, String password, String... roleNames)
//            throws UserAlreadyExistedException, MiniSecurityException {
//        // check userName
//        if (null == userName || !userName.equals(userName.trim()) || userName.length() == 0) {
//            throw new MiniSecurityException("register failed,incorrect username.");
//        }
//
//        // check password
//        if (null == password || !password.equals(password.trim()) || password.length() == 0) {
//            throw new MiniSecurityException("register failed,incorrect password.");
//        }
//
//        // check roles
//        if (roleNames.length == 0) {
//            throw new MiniSecurityException("register failed,unspecified role.");
//        }
//        for (String roleName : roleNames) {
//            if (null == roleName || !roleName.equals(roleName.trim()) || roleName.length() == 0) {
//                throw new MiniSecurityException("register failed,incorrect role.");
//            }
//        }
//
//        // check exist
//        User user = null;
//        try {
//            user = FileRealmData.loadUser(userName);
//            if (null != user) {
//                throw new UserAlreadyExistedException("register failed,the user has already existed.");
//            }
//        } catch (FileNotFoundException e) {
//            throw new MiniSecurityException("register failed,can not find authentication file.");
//        } catch (IOException e) {
//            throw new MiniSecurityException("register failed,read authentication file exception.");
//        }
//
//        String salt = String.valueOf((int) ((Math.random() * 9 + 1) * 100));
//        Object simpleHash = new SimpleHash("MD5", password, salt, 1);
//
//        try {
//            FileRealmData.addUser(userName, simpleHash.toString(), salt, roleNames);
//        } catch (FileNotFoundException e) {
//            throw new MiniSecurityException("register failed,can not find authentication file.");
//        } catch (IOException e) {
//            throw new MiniSecurityException("register failed,read authentication file exception.");
//        }
//    }
//
//    @Override
//    public void cancel(String userName)
//            throws UnAuthenticatedException, UserNotExistedException, MiniSecurityException {
//        // check authenticate
//        Subject subject = this.getSubject();
//        if (!subject.isAuthenticated()) {
//            throw new UnAuthenticatedException("cancel failed,unAuthenticated.");
//        }
//
//        // check userName
//        if (null == userName || !userName.equals(userName.trim()) || userName.length() == 0) {
//            throw new MiniSecurityException("cancel failed,incorrect username.");
//        }
//
//        // check exist
//        User user = null;
//        try {
//            user = FileRealmData.loadUser(userName.trim());
//            if (null == user) {
//                throw new UserNotExistedException("cancel failed,the user not existed.");
//            }
//        } catch (FileNotFoundException e) {
//            throw new MiniSecurityException("cancel failed,can not find authentication file.");
//        } catch (IOException e) {
//            throw new MiniSecurityException("cancel failed,read authentication file exception.");
//        }
//
//        try {
//            FileRealmData.removeUser(userName);
//        } catch (FileNotFoundException e) {
//            throw new MiniSecurityException("cancel failed,can not find authentication file.");
//        } catch (IOException e) {
//            throw new MiniSecurityException("cancel failed,read authentication file exception.");
//        }
//    }
//
//    @Override
//    public void changePassword(String userName, String password)
//            throws UnAuthenticatedException, UserNotExistedException, PasswordNotChangedException,MiniSecurityException {
//        // check authenticate
//        Subject subject = this.getSubject();
//        if (!subject.isAuthenticated()) {
//            throw new UnAuthenticatedException("change password failed,unAuthenticated.");
//        }
//
//        // check userName
//        if (null == userName || !userName.equals(userName.trim()) || userName.length() == 0) {
//            throw new MiniSecurityException("change password failed,incorrect username.");
//        }
//
//        // check password
//        if (null == password || !password.equals(password.trim()) || password.length() == 0) {
//            throw new MiniSecurityException("change password failed,incorrect password.");
//        }
//
//        // check exist
//        User user = null;
//        try {
//            user = FileRealmData.loadUser(userName);
//            if (null == user) {
//                throw new UserNotExistedException("change password failed,the user not existed.");
//            }
//        } catch (FileNotFoundException e) {
//            throw new MiniSecurityException("change password failed,can not find authentication file.");
//        } catch (IOException e) {
//            throw new MiniSecurityException("change password failed,read authentication file exception.");
//        }
//        
//        // check two password
//        if(user.getPassword().equals(new SimpleHash("MD5", password, user.getSalt(), 1).toString())){
//            throw new PasswordNotChangedException("change password failed:the new password is the same as the old one.");
//        }
//
//        String salt = String.valueOf((int) ((Math.random() * 9 + 1) * 100));
//        Object simpleHash = new SimpleHash("MD5", password, salt, 1);
//
//        try {
//            FileRealmData.changePassword(userName, simpleHash.toString(), salt);
//        } catch (FileNotFoundException e) {
//            throw new MiniSecurityException("change password failed,can not find authentication file.");
//        } catch (IOException e) {
//            throw new MiniSecurityException("change password failed,read authentication file exception.");
//        }
//    }
}
