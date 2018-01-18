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
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class FileRealmDataProvider {
    public final static String AUTHENTICATION = "authentication";
    public final static String AUTHORIZATION = "authorization";
    private static List<RoleModel> roles = null;

    static {
        roles = loadRoles();
    }

    public static UserModel loadUser(String userName) {
        URL url = FileRealmDataProvider.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            MiniLog.error("can not find authentication file:classpath/" + AUTHENTICATION);
            return null;
        }

        LineIterator iterator = null;
        try {
            iterator = FileUtils.lineIterator(new File(url.getPath()), "UTF-8");
            while (iterator.hasNext()) {
                String line = iterator.nextLine().trim();

                String p = (new StringBuilder()).append(userName).append("=(.+?),(.+)").toString();
                Pattern r = Pattern.compile(p);
                Matcher m = r.matcher(line);
                if (m.find()) {
                    String[] pwd = m.group(1).split(":");

                    UserModel user = new UserModel();
                    user.setUserName(userName);
                    user.setPassword(pwd[0]);
                    user.setSalt(pwd.length == 1 ? "" : pwd[1]);
                    for (String roleName : m.group(2).split(",")) {
                        user.getRoles().add(roleName);
                    }
                    return user;
                }
            }
        } catch (IOException e) {
            MiniLog.error("open authentication file exception.");
        } finally {
            try {
                iterator.close();
            } catch (IOException e) {
                MiniLog.error("close authentication file exception.");
            }
        }
        return null;
    }

    private static List<RoleModel> loadRoles() {
        List<RoleModel> roles = new ArrayList<RoleModel>();

        URL url = FileRealmDataProvider.class.getClassLoader().getResource(AUTHORIZATION);
        if (null == url) {
            MiniLog.error("can not find authorization file:classpath/" + AUTHORIZATION);
            return roles;
        }

        LineIterator iterator = null;
        String section = "";
        try {
            iterator = FileUtils.lineIterator(new File(url.getPath()), "UTF-8");
            while (iterator.hasNext()) {
                String line = iterator.nextLine().trim();

                if (line.matches(";.*")) {

                } else if (line.matches("\\[roles\\]")) {
                    section = "roles";
                } else if (line.matches("\\[tags\\]")) {
                    section = "tags";
                } else if (line.matches("(.+?)=(.+)")) {
                    Matcher m = Pattern.compile("(.+?)=(.+)").matcher(line);
                    m.find();

                    String key = m.group(1);
                    String val = m.group(2);

                    if ("roles".equals(section)) {
                        RoleModel role = new RoleModel();
                        role.setRoleName(key);
                        for (String permission : val.split(",")) {
                            role.getPermissions().add(permission);
                        }
                        roles.add(role);
                    }

                    if ("tags".equals(section)) {
                        for (String roleName : val.split(",")) {
                            for (RoleModel role : roles) {
                                if (roleName.equals(role.getRoleName())) {
                                    role.getTags().add(key);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            MiniLog.error("open authorization file exception.");
        } finally {
            try {
                iterator.close();
            } catch (IOException e) {
                MiniLog.error("close authorization file exception.");
            }
        }
        return roles;
    }

    public static List<String> getRolePermissions(String roleName) {
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
