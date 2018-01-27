package org.lechisoft.minifw.security;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.lechisoft.minifw.security.exception.SecurityDataException;
import org.lechisoft.minifw.security.model.Role;
import org.lechisoft.minifw.security.model.User;

public class FileSecurityData implements SecurityData {

    public final static String AUTHENTICATION = "authentication";
    public final static String AUTHORIZATION = "authorization";

    @Override
    public User getUser(String userName) throws SecurityDataException {
        URL url = FileSecurityData.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new SecurityDataException(
                    "Get user failed:Can not find authentication file:classpath/" + AUTHENTICATION);
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
            throw new SecurityDataException("Get user failed:" + e.getMessage());
        } finally {
            try {
                iterator.close();
            } catch (IOException e) {
                throw new SecurityDataException("Get user failed:" + e.getMessage());
            }
        }
        return user;
    }

    @Override
    public Role getRole(String roleName) throws SecurityDataException {
        URL url = FileSecurityData.class.getClassLoader().getResource(AUTHORIZATION);
        if (null == url) {
            throw new SecurityDataException(
                    "Get role failed:Can not find authorization file:classpath/" + AUTHORIZATION);
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
            throw new SecurityDataException("Get role failed:" + e.getMessage());
        } finally {
            try {
                iterator.close();
            } catch (IOException e) {
                throw new SecurityDataException("Get role failed:" + e.getMessage());
            }
        }
        return role;
    }

    @Override
    public void register(String userName, String password, String salt, String... roleNames)
            throws SecurityDataException {
        URL url = FileSecurityData.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new SecurityDataException(
                    "Register failed:Can not find authentication file:classpath/" + AUTHENTICATION);
        }

        File inFile = new File(url.getPath());

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

        RandomAccessFile raf = null;
        FileChannel fc = null;
        try {
            raf = new RandomAccessFile(inFile, "rw");
            fc = raf.getChannel();
            fc.position(fc.size());
            fc.write(ByteBuffer.wrap(stb.toString().getBytes()));
        } catch (FileNotFoundException e) {
            throw new SecurityDataException("Register failed:" + e.getMessage());
        } catch (IOException e) {
            throw new SecurityDataException("Register failed:" + e.getMessage());
        } finally {
            try {
                fc.close();
                raf.close();
            } catch (IOException e) {
                throw new SecurityDataException("Register failed:" + e.getMessage());
            }
        }
    }

    @Override
    public void cancelUser(String userName) throws SecurityDataException {
        URL url = FileSecurityData.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new SecurityDataException(
                    "Cancel user failed:Can not find authentication file:classpath/" + AUTHENTICATION);
        }

        File inFile = new File(url.getPath());

        String outFilePath = url.getPath().replaceAll(AUTHENTICATION, String.valueOf((new Date()).getTime()));
        File outFile = new File(outFilePath);

        boolean isFirstLine = true;
        LineIterator iterator = null;
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(outFile);

            // use LineIterator to loop the file
            iterator = FileUtils.lineIterator(inFile, "UTF-8");
            while (iterator.hasNext()) {
                String line = iterator.nextLine();
                if (line.matches(userName + "=(.+?),(.+)")) {
                    continue;
                }
                if (isFirstLine) {
                    writer.write(line);
                    isFirstLine = false;
                } else {
                    writer.write("\r\n" + line);
                }
                writer.flush();
            }
        } catch (FileNotFoundException e) {
            throw new SecurityDataException("Cancel user failed:" + e.getMessage());
        } catch (IOException e) {
            throw new SecurityDataException("Cancel user failed:" + e.getMessage());
        } finally {
            try {
                writer.close();
                iterator.close();

                // delete the old file,and rename the new file
                inFile.delete();
                outFile.renameTo(inFile);
            } catch (IOException e) {
                throw new SecurityDataException("Cancel user failed:" + e.getMessage());
            }
        }
    }

    @Override
    public void changePassword(String userName, String password, String salt) throws SecurityDataException {
        URL url = FileSecurityData.class.getClassLoader().getResource(AUTHENTICATION);
        if (null == url) {
            throw new SecurityDataException(
                    "Change password failed:Can not find authentication file:classpath/" + AUTHENTICATION);
        }

        File inFile = new File(url.getPath());

        long p = 0;
        // use LineIterator to loop the file
        LineIterator iterator = null;
        try {
            iterator = FileUtils.lineIterator(inFile, "UTF-8");

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
        } catch (IOException e) {
            throw new SecurityDataException("Change password failed:" + e.getMessage());
        } finally {
            try {
                iterator.close();
            } catch (IOException e) {
                throw new SecurityDataException("Change password failed:" + e.getMessage());
            }
        }
    }
}
