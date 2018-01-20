package org.lechisoft.minifw.security;

import java.util.Random;

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
         for (int i = 0; i < 1; i++) {
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

        try {
            miniSecurity.signin("admin", "admin");
            //miniSecurity.register("lisi5", "lisi8", "r1");
            //miniSecurity.cancel("lisi8");
            miniSecurity.changePassword("lisi5", "xx");
        } catch (Exception e) {
            MiniLog.debug("", e);
        }
    }

}