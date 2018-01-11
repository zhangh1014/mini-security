package org.lechisoft.minifw.security;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.PermissionModel;
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class XmlRealm extends AuthorizingRealm {
    private String configFilePath = "";
    Log log = null;

    // 权限、角色、用户
    private List<PermissionModel> permissions = null;
    private List<RoleModel> roles = null;

    public XmlRealm() {
        this(ConstValue.DEFAULT_PATH);
    }

    public XmlRealm(String path) {
        log = LogFactory.getLog(ConstValue.DEFAULT_LOGGER);

        URL url = this.getClass().getClassLoader().getResource(path);
        if (null == url) {
            this.log.error("can not find dir:classpath/" + path);
            return;
        }
        this.configFilePath = url.getPath();

        this.load();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal(); // 用户名
        String password = new String((char[]) token.getCredentials()); // 密码

        // if (!"zhang".equals(username)) {
        // throw new UnknownAccountException(); // 如果用户名错误
        // }
        // if (!"123".equals(password)) {
        // throw new IncorrectCredentialsException(); // 如果密码错误
        // }
        // 如果身份认证验证成功，返回一个AuthenticationInfo实现；
        return new SimpleAuthenticationInfo("zhang", "1234", this.getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {
        String lala = "fdasfas";
        lala += "a";
        // TODO Auto-generated method stub
        return null;
    }

    private void load() {
        Element root = this.getRoot();

        // 1.load permissions
        this.permissions = this.loadPermissions(root);

        // 2.load roles
        this.roles = this.loadRoles(root);
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

                            PermissionModel permission = this.getLoadedPermission(resource, action);
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

                            PermissionModel permission = this.getLoadedPermission(resource, action);
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
                    users.add(element2User(eUser));
                }
            }
        }
        return users;
    }

    private UserModel loadUser(Element root, String userId) {
        root = null == root ? this.getRoot() : root;

        for (Element e : root.elements()) {
            if (e.getName().equals("users")) {
                for (Element eUser : e.elements()) {
                    if (userId.equals(eUser.element("user_id").getText())) {
                        return element2User(eUser);
                    }
                }
            }
        }
        return null;
    }

    private UserModel element2User(Element element) {
        String userId = element.element("user_id").getText();

        String userPwd = element.element("user_pwd").getText();
        String alias = element.element("alias").getText();

        UserModel user = new UserModel();
        user.setUserId(userId);
        user.setUserPwd(userPwd);
        user.setAlias(alias);

        Element eRoles = element.element("roles");
        if (null != eRoles) {
            for (Element eRole : eRoles.elements()) {
                String roleId = eRole.getText();
                user.getRoles().add(roleId);
            }
        }
        return user;
    }

    private PermissionModel getLoadedPermission(String resource, String action) {
        for (PermissionModel permission : this.permissions) {
            if (resource.equals(permission.getResource()) && action.equals(permission.getAction())) {
                return permission;
            }
        }
        return null;
    }

}
