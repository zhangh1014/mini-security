package org.lechisoft.minifw.security;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.lechisoft.minifw.security.model.PermissionModel;
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class MiniSecurity {
    private static final String DEFAULT_LOGGER = "syslogger";
    private final static String DEFAULT_PATH = "conf/mini-security.xml";
    private String configFilePath = "";

    Log log = null;

    // 权限、角色、用户
    private List<PermissionModel> permissions = new ArrayList<PermissionModel>();
    private List<RoleModel> roles = new ArrayList<RoleModel>();
    private List<UserModel> users = new ArrayList<UserModel>();

    public MiniSecurity() {
        this(DEFAULT_PATH);
    }

    public MiniSecurity(String path) {
        log = LogFactory.getLog(DEFAULT_LOGGER);

        URL url = this.getClass().getClassLoader().getResource(path);
        if (null == url) {
            this.log.error("can not find dir:classpath/" + path);
            return;
        }
        this.configFilePath = url.getPath();

        this.load();
    }

    private void load() {

        SAXReader saxReader = new SAXReader();
        try {
            Document document = saxReader.read(this.configFilePath);
            Element root = document.getRootElement();

            // load permissions
            for (Element e : root.elements()) {
                if (e.getName().equals("permissions")) {
                    for (Element ep : e.elements()) {
                        Element eResource = ep.element("resource");
                        Element eAction = ep.element("action");
                        Element eDescription = ep.element("description");
                        Element eSort = ep.element("sort");
                        Element eRemarks = ep.element("remarks");

                        String resource = eResource.getText();
                        String action = eAction.getText();
                        String description = eDescription.getText();

                        String sort = null == eSort ? "0" : eSort.getText();
                        sort = sort.matches("^\\d+$") ? sort : "0";
                        String remarks = null == eRemarks ? "" : eRemarks.getText();

                        PermissionModel permission = new PermissionModel();
                        permission.setResource(resource);
                        permission.setAction(action);
                        permission.setDescription(description);
                        permission.setSort(Integer.parseInt(sort));
                        permission.setRemarks(remarks);
                        this.permissions.add(permission);
                    }
                }
            }

            // load permissions
            for (Element e : root.elements()) {
                if (e.getName().equals("roles")) {
                    for (Element er : e.elements()) {
                        Element eRoleId = er.element("role_id");
                        Element eRoleName = er.element("role_name");
                        Element eParentRoleId = er.element("parent_role_id");
                        Element eSort = er.element("sort");
                        Element eRemarks = er.element("remarks");

                        String roleId = eRoleId.getText();
                        String roleName = eRoleName.getText();
                        String parentRoleId = eParentRoleId.getText();

                        String sort = null == eSort ? "0" : eSort.getText();
                        sort = sort.matches("^\\d+$") ? sort : "0";
                        String remarks = null == eRemarks ? "" : eRemarks.getText();

                        RoleModel role = new RoleModel();
                        role.setRoleId(roleId);
                        role.setRoleName(roleName);
                        role.setParentRoleId(parentRoleId);
                        role.setSort(Integer.parseInt(sort));
                        role.setRemarks(remarks);

                        Element ePermissions = er.element("permissions");
                        if (null != ePermissions) {
                            for (Element ep : ePermissions.elements()) {
                                Element eResource = ep.element("resource");
                                Element eAction = ep.element("action");
                                String resource = eResource.getText();
                                String action = eAction.getText();

                                PermissionModel permission = this.getPermission(resource, action).clone();
                                if (null != permission) {
                                    role.getPermissions().add(permission);
                                }

                            }
                        }

                        this.roles.add(role);
                        //
                        //
                        //
                        // Element ePermissions = ep.element("permissions");
                        // Element eExcludePermissions =
                        // ep.element("exclude_permissions");
                        // Element eTags = ep.element("tags");
                        //
                        //
                        // PermissionModel permission = new PermissionModel();
                        // permission.setResource(resource);
                        // permission.setAction(action);
                        // permission.setDescription(description);
                        // permission.setSort(Integer.parseInt(sort));
                        // permission.setRemarks(remarks);
                        // this.permissions.add(new PermissionModel());
                    }
                }
            }

        } catch (DocumentException e) {
            this.log.error("load " + this.configFilePath + " failed.", e);
        } catch (Exception e) {
            this.log.error("load " + this.configFilePath + " failed.", e);
        }
    }

    private PermissionModel getPermission(String resource, String action) {
        for (PermissionModel permission : this.permissions) {
            if (resource.equals(permission.getResource()) && action.equals(permission.getAction())) {
                return permission;
            }
        }
        return null;
    }

    public void refresh() {
        this.load();
    }
}
