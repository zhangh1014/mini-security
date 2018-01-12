package org.lechisoft.minifw.security.model;

import java.util.ArrayList;
import java.util.List;

public class RoleModel implements Cloneable {

    public RoleModel(String roleId) {
        this.roleId = roleId;
    }

    public RoleModel clone() {
        RoleModel o = null;
        try {
            o = (RoleModel) super.clone();

            o.childRoles = new ArrayList<RoleModel>(); // 子角色
            for (RoleModel role : this.getChildRoles()) {
                o.childRoles.add(role.clone());
            }
            o.permissions = new ArrayList<PermissionModel>(); // 角色的权限
            for (PermissionModel permission : this.getPermissions()) {
                o.permissions.add(permission.clone());
            }
            o.excludePermissions = new ArrayList<PermissionModel>(); // 角色的例外权限
            for (PermissionModel permission : this.getExcludePermissions()) {
                o.excludePermissions.add(permission.clone());
            }
            o.tags = new ArrayList<String>(); // 角色的标签
            for (String tag : this.getTags()) {
                o.tags.add(tag);
            }

        } catch (CloneNotSupportedException e) {
            // already implements Cloneable
        }
        return o;
    }

    private String roleId = ""; // 角色编号
    private String roleName = ""; // 角色名称
    private String parentRoleId = ""; // 父角色编号
    private int sort = 0; // 排序
    private String remarks = ""; // 备注

    private List<RoleModel> childRoles = new ArrayList<RoleModel>(); // 子角色
    private List<PermissionModel> permissions = new ArrayList<PermissionModel>(); // 角色的权限
    private List<PermissionModel> excludePermissions = new ArrayList<PermissionModel>(); // 角色的例外权限
    private List<String> tags = new ArrayList<String>(); // 角色的标签

    public String getRoleId() {
        return roleId;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getParentRoleId() {
        return parentRoleId;
    }

    public void setParentRoleId(String parentRoleId) {
        this.parentRoleId = parentRoleId;
    }

    public int getSort() {
        return sort;
    }

    public void setSort(int sort) {
        this.sort = sort;
    }

    public String getRemarks() {
        return remarks;
    }

    public void setRemarks(String remarks) {
        this.remarks = remarks;
    }

    public List<RoleModel> getChildRoles() {
        return childRoles;
    }

    public void setChildRoles(List<RoleModel> childRoles) {
        this.childRoles = childRoles;
    }

    public List<PermissionModel> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<PermissionModel> permissions) {
        this.permissions = permissions;
    }

    public List<PermissionModel> getExcludePermissions() {
        return excludePermissions;
    }

    public void setExcludePermissions(List<PermissionModel> excludePermissions) {
        this.excludePermissions = excludePermissions;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }
}