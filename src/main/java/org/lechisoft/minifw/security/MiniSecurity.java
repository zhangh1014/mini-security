package org.lechisoft.minifw.security;

import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

import org.ini4j.Ini;
import org.ini4j.InvalidFileFormatException;

public class MiniSecurity {
    private final static String DEFAULT_PATH = "mini-security.ini";
    Ini ini;

    public MiniSecurity(){
        this(DEFAULT_PATH);
    }
    public MiniSecurity(String path){
        ini = new Ini();
        URL url = this.getClass().getClassLoader().getResource(path);
        if (null == url) {
            // TODO Log.error("can not find dir:classpath/" + DEFAULT_ROOT_PATH);
            return;
        }
        
        try {
            ini.load(url);
            
            // get users
            Map<String, String> users = ini.get("users");
            for (Entry<String, String> entry : users.entrySet()) {
                String user = entry.getKey();
                String password = entry.getValue();
               }
            
        } catch (InvalidFileFormatException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
    }
}
