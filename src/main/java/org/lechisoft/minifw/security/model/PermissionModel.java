package org.lechisoft.minifw.security.model;

public class PermissionModel implements Cloneable {

    public PermissionModel(String resource, String action, String description, int sort, String remarks) {
        this.resource = resource;
        this.action = action;
        this.description = description;
        this.sort = sort;
        this.remarks = remarks;
    }

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

    public String getAction() {
        return action;
    }

    public String getDescription() {
        return description;
    }

    public int getSort() {
        return sort;
    }

    public String getRemarks() {
        return remarks;
    }
}