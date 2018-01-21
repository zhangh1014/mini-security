package org.lechisoft.minifw.security;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.lechisoft.minifw.log.MiniLog;
import org.lechisoft.minifw.security.model.Role;
import org.lechisoft.minifw.security.model.User;

public class FileRealmData implements RealmData {

    public final static String AUTHENTICATION = "authentication";
    public final static String AUTHORIZATION = "authorization";

    @Override
    public User getUser(String userName) {
        URL url = FileRealmData.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            MiniLog.debug("Can not find authentication file:classpath/" + AUTHENTICATION);
            return null;
        }

        User user = null;
        File inFile = new File(url.getPath());
        LineIterator iterator = null;
        try {
            iterator = FileUtils.lineIterator(inFile, "UTF-8");
            while (iterator.hasNext()) {
                String line = iterator.nextLine().trim();
                Matcher m = Pattern.compile(userName + "=(.+?),(.+)").matcher(line);
                if (m.find()) {
                    String[] pwd = m.group(1).split(":");

                    user = new User();
                    user.setUserName(userName);
                    user.setPassword(pwd[0]);
                    user.setSalt(pwd[1]);
                    user.setRoles(Arrays.asList(m.group(2).split(",")));
                    break;
                }
            }
        } catch (IOException e) {
            MiniLog.debug("Read authentication file exception.");
        } finally {
            try {
                iterator.close();
            } catch (IOException e1) {
                MiniLog.debug("Close authentication file exception.");
            }
        }
        return user;
    }

    @Override
    public Role getRole(String roleName) {
        URL url = FileRealmData.class.getClassLoader().getResource(AUTHORIZATION);
        if (null == url) {
            MiniLog.debug("Can not find authorization file:classpath/" + AUTHORIZATION);
            return null;
        }

        Role role = null;
        File inFile = new File(url.getPath());
        LineIterator iterator = null;
        try {
            iterator = FileUtils.lineIterator(inFile, "UTF-8");
            while (iterator.hasNext()) {
                String line = iterator.nextLine().trim();
                Matcher m = Pattern.compile(roleName + "=(.+)").matcher(line);
                if (m.find()) {
                    role = new Role();
                    role.setRoleName(roleName);
                    role.setPermissions(Arrays.asList(m.group(1).split(",")));
                    break;
                }
            }
        } catch (IOException e) {
            MiniLog.debug("Read authorization file exception.");
        } finally {
            try {
                iterator.close();
            } catch (IOException e1) {
                MiniLog.debug("Close authorization file exception.");
            }
        }
        return role;
    }

    // private static Map<String, List<String>> roles = null;
    // private static Map<String, List<String>> tags = null;
    //
    // private boolean initAuthorizationFlg = false;
    //
    // public FileRealmData() {
    // this(false);
    // }
    //
    // public FileRealmData(boolean initAuthorizationFlg) {
    // this.initAuthorizationFlg = initAuthorizationFlg;
    // if (initAuthorizationFlg) {
    // initAuthorization();
    // }
    // }

    // private void initAuthorization() {
    // MiniLog.debug("Start loading authorization info.");
    //
    // URL url =
    // FileRealmData.class.getClassLoader().getResource(AUTHORIZATION);
    // if (null == url) {
    // MiniLog.error("Can not find authorization file:classpath/" +
    // AUTHORIZATION);
    // return;
    // }
    //
    // roles = new HashMap<String, List<String>>();
    // tags = new HashMap<String, List<String>>();
    //
    // String section = "";
    // File inFile = new File(url.getPath());
    // LineIterator iterator = null;
    // try {
    // iterator = FileUtils.lineIterator(inFile, "UTF-8");
    // while (iterator.hasNext()) {
    // String line = iterator.nextLine().trim();
    // if (line.matches(";.*")) {
    //
    // } else if (line.matches("\\[roles\\]")) {
    // section = "roles";
    // } else if (line.matches("\\[tags\\]")) {
    // section = "tags";
    // } else if (line.matches("(.+?)=(.+)")) {
    // Matcher m = Pattern.compile("(.+?)=(.+)").matcher(line);
    // m.find();
    // if ("roles".equals(section)) {
    // roles.put(m.group(1), Arrays.asList(m.group(2).split(",")));
    // }
    // if ("tags".equals(section)) {
    // tags.put(m.group(1), Arrays.asList(m.group(2).split(",")));
    // }
    // }
    // }
    // } catch (IOException e) {
    // roles = new HashMap<String, List<String>>();
    // tags = new HashMap<String, List<String>>();
    // MiniLog.error("Read authorization file exception.");
    // } finally {
    // try {
    // iterator.close();
    // } catch (IOException e1) {
    // roles = new HashMap<String, List<String>>();
    // tags = new HashMap<String, List<String>>();
    // MiniLog.error("Close authorization file exception.");
    // }
    // }
    // MiniLog.debug("Load authorization info successfully.");
    // }

    // public List<String> getRolePermissions(String roleName) throws
    // FileNotFoundException, IOException {
    // return roles.get(roleName);
    // }
    //
    // protected List<String> getTagRoles(String tag) {
    // return tags.get(tag);
    // }

    // public User loadUser(String userName) throws FileNotFoundException,
    // IOException {
    // URL url =
    // FileRealmData.class.getClassLoader().getResource(AUTHENTICATION);
    // File inFile = new File(url.getPath());
    //
    // User user = null;
    // LineIterator iterator = FileUtils.lineIterator(inFile, "UTF-8");
    // while (iterator.hasNext()) {
    // String line = iterator.nextLine().trim();
    //
    // Pattern r = Pattern.compile(userName + "=(.+?),(.+)");
    // Matcher m = r.matcher(line);
    // if (m.find()) {
    // String[] pwd = m.group(1).split(":");
    //
    // user = new User();
    // user.setUserName(userName);
    // user.setPassword(pwd[0]);
    // user.setSalt(pwd[1]);
    // for (String roleName : m.group(2).split(",")) {
    // user.getRoles().add(roleName);
    // }
    // break;
    // }
    // }
    // // close
    // iterator.close();
    // return user;
    // }

    // public void addUser(String userName, String password, String salt,
    // String... roleNames)
    // throws FileNotFoundException, IOException {
    // URL url =
    // FileRealmData.class.getClassLoader().getResource(AUTHENTICATION);
    // File inFile = new File(url.getPath());
    //
    // // make a user string
    // StringBuilder stb = new StringBuilder("\r\n");
    // stb.append(userName);
    // stb.append("=");
    // stb.append(password);
    // stb.append(":");
    // stb.append(salt);
    // for (String roleName : roleNames) {
    // stb.append(",");
    // stb.append(roleName);
    // }
    //
    // RandomAccessFile raf = new RandomAccessFile(inFile, "rw");
    // FileChannel fc = raf.getChannel();
    // fc.position(fc.size());
    // fc.write(ByteBuffer.wrap(stb.toString().getBytes()));
    // fc.close();
    // raf.close();
    // }
    //
    // public void removeUser(String userName) throws FileNotFoundException,
    // IOException {
    // URL url =
    // FileRealmData.class.getClassLoader().getResource(AUTHENTICATION);
    // File inFile = new File(url.getPath());
    //
    // String outFilePath = url.getPath().replaceAll(AUTHENTICATION,
    // String.valueOf((new Date()).getTime()));
    // File outFile = new File(outFilePath);
    // PrintWriter writer = new PrintWriter(outFile);
    //
    // boolean isFirstLine = true;
    // // use LineIterator to loop the file
    // LineIterator iterator = FileUtils.lineIterator(inFile, "UTF-8");
    // while (iterator.hasNext()) {
    // String line = iterator.nextLine();
    // if (line.matches(userName + "=(.+?),(.+)")) {
    // continue;
    // }
    // if (isFirstLine) {
    // writer.write(line);
    // isFirstLine = false;
    // } else {
    // writer.write("\r\n" + line);
    // }
    // writer.flush();
    // }
    //
    // // close
    // writer.close();
    // iterator.close();
    //
    // // delete the old file,and rename the new file
    // inFile.delete();
    // outFile.renameTo(inFile);
    // }
    //
    // public void changePassword(String userName, String password, String salt)
    // throws FileNotFoundException, IOException {
    // URL url =
    // FileRealmData.class.getClassLoader().getResource(AUTHENTICATION);
    // File inFile = new File(url.getPath());
    //
    // long p = 0;
    // // use LineIterator to loop the file
    // LineIterator iterator = FileUtils.lineIterator(inFile, "UTF-8");
    // while (iterator.hasNext()) {
    // String line = iterator.nextLine();
    // if (line.matches(userName + "=(.+?),(.+)")) {
    // p += (userName + "=").getBytes().length;
    // RandomAccessFile raf = new RandomAccessFile(inFile, "rw");
    // raf.seek(p);
    //
    // raf.write((password + ":" + salt).getBytes());
    // raf.close();
    // break;
    // }
    // p += (line + "\r\n").getBytes().length;
    // }
    //
    // // close
    // iterator.close();
    // }

}
