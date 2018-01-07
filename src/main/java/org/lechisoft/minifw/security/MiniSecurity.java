package org.lechisoft.minifw.security;

import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.lechisoft.minifw.security.common.MD5Util;
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
    // private List<UserModel> users = null;

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
        Element root = this.getRoot();

        // 1.load permissions
        this.permissions = this.loadPermissions(root);

        // 2.load roles
        this.roles = this.loadRoles(root);
    }

    private List<PermissionModel> loadPermissions(Element root) {
        root = null == root ? this.getRoot() : root;

        List<PermissionModel> permissions = new ArrayList<PermissionModel>();
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

                    PermissionModel permission = new PermissionModel(resource, action, description,
                            Integer.parseInt(sort), remarks);
                    permissions.add(permission);
                }
            }
        }
        return permissions;
    }

    private List<RoleModel> loadRoles(Element root) {
        root = null == root ? this.getRoot() : root;

        List<RoleModel> roles = new ArrayList<RoleModel>();
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

                            PermissionModel permission = this.getPermission(resource, action);
                            if (null != permission) {
                                role.getPermissions().add(permission);
                            }
                        }
                    }

                    Element eExcludePermissions = eRole.element("exclude_permissions");
                    if (null != eExcludePermissions) {
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
                    if (null != eTags) {
                        for (Element eTag : eTags.elements()) {
                            String tag = eTag.getText();
                            if (!"".equals(tag)) {
                                role.getTags().add(tag);
                            }
                        }
                    }
                    roles.add(role);
                }
            }
        }
        return roles;
    }

    private List<UserModel> loadUsers(Element root) {
        root = null == root ? this.getRoot() : root;

        List<UserModel> users = new ArrayList<UserModel>();
        for (Element e : root.elements()) {
            if (e.getName().equals("users")) {
                for (Element eUser : e.elements()) {
                    String userId = eUser.element("user_id").getText();
                    String userPwd = eUser.element("user_pwd").getText();
                    String salt = eUser.element("salt").getText();
                    String alias = eUser.element("alias").getText();

                    UserModel user = new UserModel();
                    user.setUserId(userId);
                    user.setUserPwd(userPwd);
                    user.setSalt(salt);
                    user.setAlias(alias);

                    Element eRoles = eUser.element("roles");
                    if (null != eRoles) {
                        for (Element eRole : eRoles.elements()) {
                            String roleId = eRole.getText();
                            user.getRoles().add(roleId);
                        }
                    }
                    users.add(user);
                }
            }
        }
        return users;
    }

    private Element getRoot() {
        SAXReader saxReader = new SAXReader();
        try {
            Document document = saxReader.read(this.configFilePath);
            return document.getRootElement();

        } catch (DocumentException e) {
            this.log.error("load " + this.configFilePath + " failed.", e);
        } catch (Exception e) {
            this.log.error("load " + this.configFilePath + " failed.", e);
        }
        return null;
    }

    private PermissionModel getPermission(String resource, String action) {
        for (PermissionModel permission : this.permissions) {
            if (resource.equals(permission.getResource()) && action.equals(permission.getAction())) {
                return permission;
            }
        }
        return null;
    }

    private RoleModel getRole(String roleId) {
        for (RoleModel role : this.roles) {
            if (roleId.equals(role.getRoleId())) {
                return role;
            }
        }
        return null;
    }

    private UserModel getUser(String userId) {
        Element root = this.getRoot();

        for (Element e : root.elements()) {
            if (e.getName().equals("users")) {
                for (Element eUser : e.elements()) {
                    String _userId = eUser.element("user_id").getText();
                    if (_userId.equals(userId)) {
                        String userPwd = eUser.element("user_pwd").getText();
                        String alias = eUser.element("alias").getText();

                        UserModel user = new UserModel();
                        user.setUserId(_userId);
                        user.setUserPwd(userPwd);
                        user.setAlias(alias);

                        Element eRoles = eUser.element("roles");
                        if (null != eRoles) {
                            for (Element eRole : eRoles.elements()) {
                                String roleId = eRole.getText();
                                user.getRoles().add(roleId);
                            }
                        }
                        return user;
                    }
                }
            }
        }
        return null;
    }

    public void reload() {
        this.load();
    }

    @Override
    public void login(String userName, String password) throws Exception {
        if("".equals(userName.trim())){
            throw new Exception("error user name.");
        }
        
        if("".equals(password.trim())){
            throw new Exception("error password.");
        }
        
        UserModel user = this.getUser(userName);
        if(null == user){
            throw new Exception("no user.");
        }
        
        String userPwd = MD5Util.getMD5(password, user.getSalt());
        if(!userPwd.equals(user.getUserPwd())){
            throw new Exception("incorrect password.");
        }
        
    }
}
