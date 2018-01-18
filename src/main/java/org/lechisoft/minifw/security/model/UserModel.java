package org.lechisoft.minifw.security.model;

import java.util.ArrayList;
import java.util.List;

public class UserModel implements Cloneable {

    private String userName = ""; // user name
    private String password = ""; // password
    private String salt = ""; // salt
    private List<String> roles = new ArrayList<String>(); // user's roles

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}