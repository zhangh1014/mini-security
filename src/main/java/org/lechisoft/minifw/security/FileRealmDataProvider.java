package org.lechisoft.minifw.security;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.apache.shiro.authc.UnknownAccountException;
import org.lechisoft.minifw.log.MiniLog;
import org.lechisoft.minifw.security.model.RoleModel;
import org.lechisoft.minifw.security.model.UserModel;

public class FileRealmDataProvider {
    public final static String AUTHENTICATION = "authentication";
    public final static String AUTHORIZATION = "authorization";
    private static List<RoleModel> roles = null;

    static {
        try {
            roles = loadRoles();
        } catch (IOException e) {
            MiniLog.error(e.getMessage());
        } finally {
            if (null == roles) {
                roles = new ArrayList<RoleModel>();
            }
        }
    }

    public static UserModel loadUser(String userName)
            throws FileNotFoundException, IOException, UnknownAccountException {
        URL url = FileRealmDataProvider.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new FileNotFoundException("can not find authentication file:classpath/" + AUTHENTICATION);
        }

        File inFile = new File(url.getPath());
        LineIterator iterator = FileUtils.lineIterator(inFile, "UTF-8");
        while (iterator.hasNext()) {
            String line = iterator.nextLine().trim();

            Pattern r = Pattern.compile(userName + "=(.+?),(.+)");
            Matcher m = r.matcher(line);
            if (m.find()) {
                String[] pwd = m.group(1).split(":");

                UserModel user = new UserModel();
                user.setUserName(userName);
                user.setPassword(pwd[0]);
                user.setSalt(pwd[1]);
                for (String roleName : m.group(2).split(",")) {
                    user.getRoles().add(roleName);
                }
                return user;
            }
        }
        throw new UnknownAccountException("no user:" + userName);
    }

    private static List<RoleModel> loadRoles() throws FileNotFoundException, IOException {
        URL url = FileRealmDataProvider.class.getClassLoader().getResource(AUTHORIZATION);
        if (null == url) {
            throw new FileNotFoundException("can not find authorization file:classpath/" + AUTHORIZATION);
        }

        List<RoleModel> roles = new ArrayList<RoleModel>();

        String section = "";
        File inFile = new File(url.getPath());
        LineIterator iterator = FileUtils.lineIterator(inFile, "UTF-8");
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
        return roles;
    }

    public static RoleModel getRole(String roleName) {
        for (RoleModel role : roles) {
            if (roleName.equals(role.getRoleName())) {
                return role;
            }
        }
        return null;
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

    public static void addUser(String userName, String password, String salt, String... roleNames) throws IOException {
        // check file exist
        URL url = FileRealmDataProvider.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new FileNotFoundException("can not find authentication file:classpath/" + AUTHENTICATION);
        }

        // make a user string
        StringBuilder stb = new StringBuilder("\r\n");
        stb.append(userName);
        stb.append("=");
        stb.append(password);
        stb.append(":");
        stb.append(salt);
        for (String roleName : roleNames) {
            stb.append(",");
            stb.append(roleName);
        }

        RandomAccessFile raf = new RandomAccessFile(url.getPath(), "rw");
        FileChannel fc = raf.getChannel();
        fc.position(fc.size());
        fc.write(ByteBuffer.wrap(stb.toString().getBytes()));
        fc.close();
        raf.close();
    }

    public static void removeUser(String userName) throws IOException {
        // check file exist
        URL url = FileRealmDataProvider.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new FileNotFoundException("can not find authentication file:classpath/" + AUTHENTICATION);
        }

        File inFile = new File(url.getPath());
        String outFilePath = url.getPath().replaceAll(AUTHENTICATION, String.valueOf((new Date()).getTime()));
        File outFile = new File(outFilePath);
        PrintWriter writer = new PrintWriter(outFile);

        // use LineIterator to loop the file
        LineIterator iterator = FileUtils.lineIterator(inFile, "UTF-8");
        while (iterator.hasNext()) {
            String line = iterator.nextLine().trim();
            if (line.matches(userName + "=(.+?),(.+)")) {
                continue;
            }
            writer.println(line);
            writer.flush();
        }

        writer.close();
        iterator.close();

        // delete the old file,and rename the new file
        inFile.delete();
        outFile.renameTo(inFile);
    }

    public static void changePassword(String userName, String password, String salt) throws IOException {
        // check file exist
        URL url = FileRealmDataProvider.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new FileNotFoundException("can not find authentication file:classpath/" + AUTHENTICATION);
        }

        File inFile = new File(url.getPath());
        long p = 0;
        // use LineIterator to loop the file
        LineIterator iterator = FileUtils.lineIterator(inFile, "UTF-8");
        while (iterator.hasNext()) {
            String line = iterator.nextLine();
            if (line.matches(userName + "=(.+?),(.+)")) {
                p += (userName + "=").getBytes().length;
                RandomAccessFile raf = new RandomAccessFile(inFile, "rw");
                raf.seek(p);

                raf.write((password + ":" + salt).getBytes());
                raf.close();
                break;
            }
            p += (line + "\r\n").getBytes().length;
        }
        iterator.close();
    }
}
