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

public class MiniSecurity implements IMiniSecurity {
    
    private static final String DEFAULT_LOGGER = "syslogger";
    private final static String DEFAULT_PATH = "conf/mini-security.xml";
    private String configFilePath = "";

    Log log = null;

    // 权限、角色、用户
    private List<PermissionModel> permissions = null;
    private List<RoleModel> roles = null;
    private List<UserModel> users = null;

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

            // 1.load permissions
            this.loadPermissions(root);

            // 2.load roles
            this.loadRoles(root);

            // 3.load users
            this.loadUsers(root);

        } catch (DocumentException e) {
            this.log.error("load " + this.configFilePath + " failed.", e);
        } catch (Exception e) {
            this.log.error("load " + this.configFilePath + " failed.", e);
        }
    }

    private void loadPermissions(Element root) {
        this.permissions = new ArrayList<PermissionModel>();

        for (Element e : root.elements()) {
            if (e.getName().equals("permissions")) {
                for (Element ePermission : e.elements()) {
                    Element eResource = ePermission.element("resource");
                    Element eAction = ePermission.element("action");
                    Element eDescription = ePermission.element("description");
                    Element eSort = ePermission.element("sort");
                    Element eRemarks = ePermission.element("remarks");

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
    }

    private void loadRoles(Element root) {
        this.roles = new ArrayList<RoleModel>();

        for (Element e : root.elements()) {
            if (e.getName().equals("roles")) {
                for (Element eRole : e.elements()) {
                    Element eRoleId = eRole.element("role_id");
                    Element eRoleName = eRole.element("role_name");
                    Element eParentRoleId = eRole.element("parent_role_id");
                    Element eSort = eRole.element("sort");
                    Element eRemarks = eRole.element("remarks");

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

                    Element ePermissions = eRole.element("permissions");
                    if (null != ePermissions) {
                        for (Element ePermission : ePermissions.elements()) {
                            String resource = ePermission.element("resource").getText();
                            String action = ePermission.element("action").getText();

                            PermissionModel permission = this.getPermission(resource, action).clone();
                            if (null != permission) {
                                role.getPermissions().add(permission);
                            }
                        }
                    }

                    Element eExcludePermissions = eRole.element("exclude_permissions");
                    if (null != ePermissions) {
                        for (Element ePermission : eExcludePermissions.elements()) {
                            String resource = ePermission.element("resource").getText();
                            String action = ePermission.element("action").getText();

                            PermissionModel permission = this.getPermission(resource, action);
                            if (null != permission) {
                                role.getExcludePermissions().add(permission);
                            }
                        }
                    }

                    Element eTags = eRole.element("tags");
                    if (null != ePermissions) {
                        for (Element eTag : eTags.elements()) {
                            String tag = eTag.getText();
                            if (!"".equals(tag)) {
                                role.getTags().add(tag);
                            }
                        }
                    }
                    this.roles.add(role);
                }
            }
        }
    }

    private void loadUsers(Element root) {
        this.users = new ArrayList<UserModel>();

        for (Element e : root.elements()) {
            if (e.getName().equals("users")) {
                for (Element eUser : e.elements()) {
                    String userId = eUser.element("user_id").getText();
                    String userPwd = eUser.element("user_pwd").getText();
                    String alias = eUser.element("alias").getText();

                    UserModel user = new UserModel();
                    user.setUserId(userId);
                    user.setUserPwd(userPwd);
                    user.setAlias(alias);

                    Element eRoles = eUser.element("roles");
                    if (null != eRoles) {
                        for (Element eRole : eRoles.elements()) {
                            String roleId = eRole.getText();
                            user.getRoles().add(roleId);
                        }
                    }
                    this.users.add(user);
                }
            }
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

    public void reload() {
        this.load();
    }
}
