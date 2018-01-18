package org.lechisoft.minifw.security.model;

import java.util.ArrayList;
import java.util.List;

public class RoleModel {

    private String roleName = ""; // 角色名称
    private List<String> permissions = new ArrayList<String>(); // 角色的权限
    private List<String> tags = new ArrayList<String>(); // 角色的标签
    
    public RoleModel(String roleName) {
        this.roleName = roleName;
    }

    public String getRoleName() {
        return roleName;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }
}