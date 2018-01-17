package org.lechisoft.minifw.security;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Test;

public class AppTest {
    @Test
    public void Test() {

//        Thread t = new Thread(new MyThread());
//        t.start();
    }
    
    public static void main(String[] args) {
        
        for(int i=0;i<1000;i++){
            MyThread myThread = new MyThread();
            myThread.start();
        }
    }
}

class MyThread extends Thread {

    public void run() {
        
        
        //System.out.println("lalalala");
        SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss:SSS");

        
        
        for (int i = 0; i < 10; i++) {
            String formatStr = formatter.format(new Date());
            System.out.println("xxx"+formatStr);
            
            MiniSecurity miniSecurity = new MiniSecurity();
            miniSecurity.login("admin", "admin");
            
            formatStr = formatter.format(new Date());
            System.out.println("xxx"+formatStr);
        }
        
    }

}