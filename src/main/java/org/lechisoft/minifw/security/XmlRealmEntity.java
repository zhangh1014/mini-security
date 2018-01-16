package org.lechisoft.minifw.security;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.PermissionModel;
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class XmlRealmEntity {
    private String configFilePath = "";
    Log log = null;

    // 权限、角色、用户
    private List<PermissionModel> permissions = null;
    private List<RoleModel> roles = null;
    private List<UserModel> users = null;

    public XmlRealmEntity() {
        this(ConstValue.DEFAULT_PATH);
    }

    public XmlRealmEntity(String path) {
        log = LogFactory.getLog(ConstValue.DEFAULT_LOGGER);

        URL url = this.getClass().getClassLoader().getResource(path);
        if (null == url) {
            this.log.error("can not find dir:classpath/" + path);
            return;
        }
        this.configFilePath = url.getPath();
        this.load(this.configFilePath);
    }
    
    private Element getRootElement(String path) {
        SAXReader saxReader = new SAXReader();
        try {
            Document document = saxReader.read(path);
            return document.getRootElement();

        } catch (DocumentException e) {
            this.log.error("load " + path + " failed.", e);
        } catch (Exception e) {
            this.log.error("load " + path + " failed.", e);
        }
        return null;
    }

    public void load(String path) {
        Element root = this.getRootElement(path);

        // 1.load permissions
        this.loadPermissions(root);

        // 2.load roles
        this.loadRoles(root);
        
        // 3.load users
        this.loadUsers(root);
        
        root=null;
    }

    private void loadPermissions(Element root) {
        this.permissions = new ArrayList<PermissionModel>();
        Element ePermissions = root.element("permissions");
        if (null != ePermissions) {
            for (Element ePermission : ePermissions.elements()) {
                permissions.add(element2Permission(ePermission));
            }
        }
    }

    /**
     * make permission object by permission element
     * 
     * @param element
     *            permission element
     * @return permission object
     */
    private PermissionModel element2Permission(Element element) {
        Element eResource = element.element("resource");
        Element eAction = element.element("action");
        Element eDescription = element.element("description");
        Element eSort = element.element("sort");
        Element eRemarks = element.element("remarks");

        String resource = eResource.getText();
        String action = eAction.getText();
        String description = eDescription.getText();

        String sort = null == eSort ? "0" : eSort.getText();
        sort = sort.matches("^\\d+$") ? sort : "0";
        String remarks = null == eRemarks ? "" : eRemarks.getText();

        PermissionModel permission = new PermissionModel(resource, action);
        permission.setDescription(description);
        permission.setSort(Integer.parseInt(sort));
        permission.setRemarks(remarks);
        return permission;
    }

    private PermissionModel getPermission(String resource, String action) {
        for (PermissionModel permission : this.permissions) {
            if (resource.equals(permission.getResource()) && action.equals(permission.getAction())) {
                return permission;
            }
        }
        return null;
    }

    /**
     * load all roles
     * 
     * @param root
     *            root element of configuration
     * @return list of roles
     */
    private void loadRoles(Element root) {
        this.roles = new ArrayList<RoleModel>();
        Element eRoles = root.element("roles");
        if (null != eRoles) {
            for (Element eRole : eRoles.elements()) {
                roles.add(element2Role(eRole));
            }
        }
    }

    /**
     * load role by role id
     * 
     * @param root
     *            root element of configuration
     * @param roleId
     *            role id
     * @return role object
     */
//    private RoleModel loadRole(Element root, String roleId) {
//        root = null == root ? this.getRoot() : root;
//
//        Element eRoles = root.element("roles");
//        if (null != eRoles) {
//            for (Element eRole : eRoles.elements()) {
//                if (roleId.equals(eRole.element("role_id").getText())) {
//                    return element2Role(eRole);
//                }
//            }
//        }
//        return null;
//    }

    /**
     * make role object by role element
     * 
     * @param element
     *            role element
     * @return role object
     */
    private RoleModel element2Role(Element element) {
        Element eRoleId = element.element("role_id");
        Element eRoleName = element.element("role_name");
        Element eParentRoleId = element.element("parent_role_id");
        Element eSort = element.element("sort");
        Element eRemarks = element.element("remarks");

        String roleId = eRoleId.getText();
        String roleName = eRoleName.getText();
        String parentRoleId = eParentRoleId.getText();

        String sort = null == eSort ? "0" : eSort.getText();
        sort = sort.matches("^\\d+$") ? sort : "0";
        String remarks = null == eRemarks ? "" : eRemarks.getText();

        RoleModel role = new RoleModel(roleId);
        role.setRoleName(roleName);
        role.setParentRoleId(parentRoleId);
        role.setSort(Integer.parseInt(sort));
        role.setRemarks(remarks);

        Element ePermissions = element.element("permissions");
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

        Element eExcludePermissions = element.element("exclude_permissions");
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

        Element eTags = element.element("tags");
        if (null != eTags) {
            for (Element eTag : eTags.elements()) {
                String tag = eTag.getText();
                if (!"".equals(tag)) {
                    role.getTags().add(tag);
                }
            }
        }
        return role;
    }
    
    private RoleModel getRole(String roleId) {
        for (RoleModel role : this.roles) {
            if (roleId.equals(role.getRoleId())) {
                return role;
            }
        }
        return null;
    }

    /**
     * load all users
     * 
     * @param root
     *            root element of configuration
     * @return list of users
     */
    private void loadUsers(Element root) {
        this.users = new ArrayList<UserModel>();
        Element eUsers = root.element("users");
        if (null != eUsers) {
            for (Element eUser : eUsers.elements()) {
                users.add(element2User(eUser));
            }
        }
    }

    /**
     * load user by user id
     * 
     * @param root
     *            root element of configuration
     * @param userId
     *            user id
     * @return user object
     */
//    private UserModel loadUser(Element root, String userName) {
//        root = null == root ? this.getRoot() : root;
//
//        Element eUsers = root.element("users");
//        if (null != eUsers) {
//            for (Element eUser : eUsers.elements()) {
//                if (userName.equals(eUser.element("user_name").getText())) {
//                    return element2User(eUser);
//                }
//            }
//        }
//        return null;
//    }

    /**
     * make user object by user element
     * 
     * @param element
     *            user element
     * @return user object
     */
    private UserModel element2User(Element element) {

        Element eUserName = element.element("user_name");
        Element ePassword = element.element("password");
        Element eSalt = element.element("salt");
        Element eAlias = element.element("alias");
        Element eRemarks = element.element("remarks");

        String userName = eUserName.getText();
        String password = ePassword.getText();
        String salt = eSalt.getText();
        String alias = null == eAlias ? userName : eAlias.getText();
        String remarks = null == eRemarks ? "" : eRemarks.getText();

        UserModel user = new UserModel(userName);
        user.setPassword(password);
        user.setSalt(salt);
        user.setAlias(alias);
        user.setRemarks(remarks);

        Element eRoles = element.element("roles");
        if (null != eRoles) {
            for (Element eRole : eRoles.elements()) {
                String roleId = eRole.getText();
                
                RoleModel role = this.getRole(roleId);
                if (null != role) {
                    user.getRoles().add(role);
                }
            }
        }
        return user;
    }
    
    private UserModel getUser(String userName) {
        for (UserModel user : this.users) {
            if (userName.equals(user.getUserName())) {
                return user;
            }
        }
        return null;
    }

    public void addUser(UserModel user) {
        Element root = this.getRootElement(this.configFilePath);

        Element eUsers = root.element("users");
        if (null == eUsers) {
            eUsers = root.addElement("users");
        }

        Element eUserName = eUsers.addElement("user_name");
        Element ePassword = eUsers.addElement("password");
        Element eSalt = eUsers.addElement("salt");
        Element eAlias = eUsers.addElement("alias");
        Element eRemarks = eUsers.addElement("remarks");

        eUserName.setText(user.getUserName());
        ePassword.setText(user.getPassword());
        eSalt.setText(user.getSalt());
        eAlias.setText(user.getAlias());
        eRemarks.setText(user.getRemarks());

        if (user.getRoles().size() > 0) {
            Element eRoles = eUsers.addElement("roles");
            for (RoleModel role : user.getRoles()) {
                role = this.getRole(role.getRoleId());
                Element eRole = eRoles.addElement("role");
                eRole.setText(role.getRoleId());
            }
        }

        // save
        this.save(root.getDocument());

        
    }
    
    private void save(Document doc){
        try {
            // save xml
            OutputFormat format = OutputFormat.createPrettyPrint();
            format.setEncoding("utf-8");
            OutputStream stream = new FileOutputStream(this.configFilePath);
            XMLWriter xmlWriter = new XMLWriter(stream, format);
            xmlWriter.write(doc);
            xmlWriter.close();
        } catch (IOException e) {
            this.log.error("write " + this.configFilePath + " failed.", e);
        }
    }

}
