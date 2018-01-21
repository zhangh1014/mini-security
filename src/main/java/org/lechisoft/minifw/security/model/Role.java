package org.lechisoft.minifw.security.model;

import java.util.ArrayList;
import java.util.List;

public class Role implements Cloneable {

    private String roleName = ""; // role name
    private List<String> permissions = new ArrayList<String>(); // role's
                                                                // permissions

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
}