package org.lechisoft.minifw.security;

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
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.lechisoft.minifw.log.MiniLog;
import org.lechisoft.minifw.security.exception.IncorrectPasswordException;
import org.lechisoft.minifw.security.exception.MiniSecurityException;
import org.lechisoft.minifw.security.exception.PasswordNotChangedException;
import org.lechisoft.minifw.security.exception.SecurityDataException;
import org.lechisoft.minifw.security.exception.UnAuthenticatedException;
import org.lechisoft.minifw.security.exception.UserAlreadyExistedException;
import org.lechisoft.minifw.security.exception.UserNotExistedException;
import org.lechisoft.minifw.security.model.User;

public class MiniSecurity {

    private List<SecurityData> data = new ArrayList<SecurityData>();
    private List<Realm> realms = new ArrayList<Realm>();

    public MiniSecurity(SecurityData... data) {
        MiniLog.debug(MiniSecurity.class.getName() + " -> " + Thread.currentThread().getStackTrace()[1].getMethodName()
                + " begin.");

        for (SecurityData sd : data) {
            this.data.add(sd);
            this.realms.add(new MiniRealm(sd));
        }

        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealms(this.realms);
        SecurityUtils.setSecurityManager(securityManager);

        MiniLog.debug(MiniSecurity.class.getName() + " -> " + Thread.currentThread().getStackTrace()[1].getMethodName()
                + " end.");
    }

    public MiniSecurity(Realm... realms) {
        MiniLog.debug(MiniSecurity.class.getName() + " -> " + Thread.currentThread().getStackTrace()[1].getMethodName()
                + " begin.");

        this.realms = Arrays.asList(realms);
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealms(this.realms);
        SecurityUtils.setSecurityManager(securityManager);

        MiniLog.debug(MiniSecurity.class.getName() + " -> " + Thread.currentThread().getStackTrace()[1].getMethodName()
                + " end.");
    }

    public List<SecurityData> getData() {
        return data;
    }

    public void setData(List<SecurityData> data) {
        this.data = data;
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
            throw new UserNotExistedException("Signin failed:the user does not exist.");
        } catch (IncorrectCredentialsException e) {
            throw new IncorrectPasswordException("Signin failed:incorrect password.");
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

    public void register(String userName, String password, String... roleNames)
            throws UserAlreadyExistedException, MiniSecurityException {

        // check userName
        if (null == userName || !userName.equals(userName.trim()) || userName.length() == 0) {
            throw new MiniSecurityException("Register failed:incorrect username.");
        }

        // check password
        if (null == password || !password.equals(password.trim()) || password.length() == 0) {
            throw new MiniSecurityException("Register failed:incorrect password.");
        }

        // check roles
        if (roleNames.length == 0) {
            throw new MiniSecurityException("Register failed:unspecified role.");
        }
        for (String roleName : roleNames) {
            if (null == roleName || !roleName.equals(roleName.trim()) || roleName.length() == 0) {
                throw new MiniSecurityException("Register failed:incorrect role.");
            }
        }

        // check exist
        for (SecurityData sd : this.data) {
            User user = null;
            try {
                user = sd.getUser(userName);
                if (null != user) {
                    throw new UserAlreadyExistedException("Register failed:the user has already existed.");
                }
            } catch (SecurityDataException e) {
                throw new MiniSecurityException(e.getMessage());
            }
        }

        // register
        for (SecurityData sd : this.data) {
            try {
                String salt = String.valueOf((int) ((Math.random() * 9 + 1) * 100));
                Object simpleHash = new SimpleHash("MD5", password, salt, 1);

                sd.register(userName, simpleHash.toString(), salt, roleNames);
            } catch (SecurityDataException e) {
                throw new MiniSecurityException(e.getMessage());
            }
        }
    }

    public void cancelUser(String userName)
            throws UnAuthenticatedException, UserNotExistedException, MiniSecurityException {

        // check authenticate
        Subject subject = this.getSubject();
        if (!subject.isAuthenticated()) {
            throw new UnAuthenticatedException("Cancel user failed:unAuthenticated.");
        }

        // check userName
        if (null == userName || !userName.equals(userName.trim()) || userName.length() == 0) {
            throw new MiniSecurityException("Cancel user failed:incorrect username.");
        }

        // check exist
        for (SecurityData sd : this.data) {
            User user = null;
            try {
                user = sd.getUser(userName);
                if (null == user) {
                    throw new UserNotExistedException("Cancel user failed:the user not existed.");
                }
            } catch (SecurityDataException e) {
                throw new MiniSecurityException(e.getMessage());
            }
        }

        // cancel
        for (SecurityData sd : this.data) {
            try {
                sd.cancelUser(userName);
            } catch (SecurityDataException e) {
                throw new MiniSecurityException(e.getMessage());
            }
        }
    }

    public void changePassword(String userName, String password) throws UnAuthenticatedException,
            UserNotExistedException, PasswordNotChangedException, MiniSecurityException {

        // check authenticate
        Subject subject = this.getSubject();
        if (!subject.isAuthenticated()) {
            throw new UnAuthenticatedException("Change password failed:unAuthenticated.");
        }

        // check userName
        if (null == userName || !userName.equals(userName.trim()) || userName.length() == 0) {
            throw new MiniSecurityException("Change password failed:incorrect username.");
        }

        // check password
        if (null == password || !password.equals(password.trim()) || password.length() == 0) {
            throw new MiniSecurityException("Change password failed:incorrect password.");
        }

        // check exist
        for (SecurityData sd : this.data) {
            User user = null;
            try {
                user = sd.getUser(userName);
                if (null == user) {
                    throw new UserNotExistedException("Change password failed:the user not existed.");
                }

                // check two password
                if (user.getPassword().equals(new SimpleHash("MD5", password, user.getSalt(), 1).toString())) {
                    throw new PasswordNotChangedException(
                            "Change password failed:the new password is the same as the old one.");
                }
            } catch (SecurityDataException e) {
                throw new MiniSecurityException(e.getMessage());
            }
        }

        // change password
        for (SecurityData sd : this.data) {
            String salt = String.valueOf((int) ((Math.random() * 9 + 1) * 100));
            Object simpleHash = new SimpleHash("MD5", password, salt, 1);

            try {
                sd.changePassword(userName, simpleHash.toString(), salt);
            } catch (SecurityDataException e) {
                throw new MiniSecurityException(e.getMessage());
            }
        }
    }
}
