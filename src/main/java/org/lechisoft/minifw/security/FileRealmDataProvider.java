package org.lechisoft.minifw.security;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.lechisoft.minifw.log.MiniLog;
import org.lechisoft.minifw.security.common.ConstValue;
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class FileRealmDataProvider {
    private static List<RoleModel> roles = null;

    static {
        roles = loadAuthorizationInfo();
    }

    public static UserModel loadAuthenticationInfo(String userName) {
        URL url = FileRealmDataProvider.class.getClassLoader().getResource(ConstValue.AUTHENTICATION_INFO);
        File file = new File(url.getPath());
        LineIterator li = null;
        try {
            li = FileUtils.lineIterator(file, "UTF-8");
            while (li.hasNext()) {
                String line = li.nextLine();

                String pattern = "^" + userName + "=(.+?),(.+)$";
                Pattern r = Pattern.compile(pattern);
                Matcher m = r.matcher(line);
                if (m.find()) {
                    UserModel user = new UserModel(userName);

                    String password = m.group(1);
                    String salt = "";
                    if (password.indexOf(":") != -1) {
                        salt = password.split(":")[1];
                        password = password.split(":")[0];
                    }
                    user.setPassword(password);
                    user.setSalt(salt);

                    String roles = m.group(2);
                    for (String role : roles.split(",")) {
                        user.getRoles().add(role);
                    }
                    return user;
                }
            }
            return null;
        } catch (IOException e) {
            MiniLog.error("can not find authentication file:classpath/" + ConstValue.AUTHENTICATION_INFO);
            return null;
        } finally {
            try {
                li.close();
            } catch (IOException e) {
                MiniLog.error("close authentication file IOException.");
            }
        }
    }

    private static List<RoleModel> loadAuthorizationInfo() {
        List<RoleModel> roles = new ArrayList<RoleModel>();

        URL url = FileRealmDataProvider.class.getClassLoader().getResource(ConstValue.AUTHORIZATION_INFO);
        File file = new File(url.getPath());
        LineIterator li = null;
        try {
            String section = "";
            li = FileUtils.lineIterator(file, "UTF-8");
            while (li.hasNext()) {
                String line = li.nextLine().trim();

                if (line.matches("^\\[roles\\]$")) {
                    section = "roles";
                    continue;
                }
                if (line.matches("^\\[tags\\]$")) {
                    section = "tags";
                    continue;
                }

                if (line.startsWith(";")) {
                    continue;
                }

                if (line.matches("^(.+?)=(.+)$")) {
                    Pattern r = Pattern.compile("^(.+?)=(.+)$");
                    Matcher m = r.matcher(line);
                    if (m.find()) {
                        String key = m.group(1);
                        String values = m.group(2);

                        if ("roles".equals(section)) {
                            RoleModel role = new RoleModel(key);
                            for (String perm : values.split(",")) {
                                role.getPermissions().add(perm);
                            }
                            roles.add(role);
                        }

                        if ("tags".equals(section)) {
                            for (String roleName : values.split(",")) {
                                for (RoleModel role : roles) {
                                    if (roleName.equals(role.getRoleName())) {
                                        role.getTags().add(key);
                                        break;
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
            }
        } catch (IOException e) {
            MiniLog.error("can not find authentication file:classpath/" + ConstValue.AUTHENTICATION_INFO);
        } finally {
            try {
                li.close();
            } catch (IOException e) {
                MiniLog.error("close authentication file IOException.");
            }
        }
        return roles;
    }

    public static List<String> getPermissions(String roleName) {
        for (RoleModel role : roles) {
            if (roleName.equals(role.getRoleName())) {
                return role.getPermissions();
            }
        }
        return new ArrayList<String>();
    }

    public static List<String> getTagRoles(String tag) {
        List<String> lst = new ArrayList<String>();
        for (RoleModel role : roles) {
            for (String itemTag : role.getTags()) {
                if (itemTag.equals(tag)) {
                    lst.add(role.getRoleName());
                    break;
                }
            }
        }
        return lst;
    }
}
