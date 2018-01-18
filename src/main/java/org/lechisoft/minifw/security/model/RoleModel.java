package org.lechisoft.minifw.security.model;

import java.util.ArrayList;
import java.util.List;

public class RoleModel {

    private String roleName = ""; // role name
    private List<String> permissions = new ArrayList<String>(); // role's permissions
    private List<String> tags = new ArrayList<String>(); // role's tags

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
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