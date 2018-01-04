package org.lechisoft.minifw.security.model;

import java.util.ArrayList;
import java.util.List;

public class UserModel implements Cloneable {

    public UserModel clone() {
        UserModel o = null;
        try {
            o = (UserModel) super.clone();
            o.roles = new ArrayList<String>(); // 用户的角色
            for (String role : this.getRoles()) {
                o.roles.add(role);
            }
        } catch (CloneNotSupportedException e) {
            // already implements Cloneable
        }
        return o;
    }

    private String userId = ""; // 用户编号
    private String userPwd = ""; // 用户密码
    private String alias = ""; // 别名
    private String remarks = ""; // 备注
    private String confirmPwd = ""; // 确认密码
    //private String confirmPwd = ""; // 确认密码

    private Object field = null; // 扩展字段
    private Object field2 = null; // 扩展字段2
    private Object field3 = null; // 扩展字段3
    private Object field4 = null; // 扩展字段4
    private Object field5 = null; // 扩展字段5

    private List<String> roles = new ArrayList<String>(); // 用户的角色

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserPwd() {
        return userPwd;
    }

    public void setUserPwd(String userPwd) {
        this.userPwd = userPwd;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getRemarks() {
        return remarks;
    }

    public void setRemarks(String remarks) {
        this.remarks = remarks;
    }

    public String getConfirmPwd() {
        return confirmPwd;
    }

    public void setConfirmPwd(String confirmPwd) {
        this.confirmPwd = confirmPwd;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public Object getField() {
        return field;
    }

    public void setField(Object field) {
        this.field = field;
    }

    public Object getField2() {
        return field2;
    }

    public void setField2(Object field2) {
        this.field2 = field2;
    }

    public Object getField3() {
        return field3;
    }

    public void setField3(Object field3) {
        this.field3 = field3;
    }

    public Object getField4() {
        return field4;
    }

    public void setField4(Object field4) {
        this.field4 = field4;
    }

    public Object getField5() {
        return field5;
    }

    public void setField5(Object field5) {
        this.field5 = field5;
    }
}