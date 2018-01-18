package org.lechisoft.minifw.security;

import java.util.List;

import org.junit.Test;
import org.lechisoft.minifw.log.MiniLog;

public class AppTest {
    @Test
    public void Test() {

        // Thread t = new Thread(new MyThread());
        // t.start();
    }

    public static void main(String[] args) {
        MiniSecurity miniSecurity = new MiniSecurity();
        for (int i = 0; i < 10; i++) {
            MyThread myThread = new MyThread(miniSecurity);
            myThread.start();
        }

    }
}

class MyThread extends Thread {
    private MiniSecurity miniSecurity = null;

    public MyThread(MiniSecurity miniSecurity) {
        this.miniSecurity = miniSecurity;
    }

    public void run() {
        this.miniSecurity.login("admin", "admin");
        List<String> roles = this.miniSecurity.getTagRoles("lala");

        MiniLog.debug(roles.toString());
    }

}