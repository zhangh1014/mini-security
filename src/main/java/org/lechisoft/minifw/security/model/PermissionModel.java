package org.lechisoft.minifw.security.model;

public class PermissionModel implements Cloneable {

    public PermissionModel clone() {
        PermissionModel o = null;
        try {
            o = (PermissionModel) super.clone();
        } catch (CloneNotSupportedException e) {
            // already implements Cloneable
        }
        return o;
    }

    private String resource = ""; // 资源
    private String action = ""; // 动作
    private String description = ""; // 描述
    private int sort = 0; // 排序
    private String remarks = ""; // 备注

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
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
}