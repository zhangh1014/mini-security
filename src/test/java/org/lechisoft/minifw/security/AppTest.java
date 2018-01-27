package org.lechisoft.minifw.security;

import org.junit.Test;
import org.lechisoft.minifw.log.MiniLog;
import org.lechisoft.minifw.security.exception.IncorrectPasswordException;
import org.lechisoft.minifw.security.exception.MiniSecurityException;
import org.lechisoft.minifw.security.exception.PasswordNotChangedException;
import org.lechisoft.minifw.security.exception.UnAuthenticatedException;
import org.lechisoft.minifw.security.exception.UserAlreadyExistedException;
import org.lechisoft.minifw.security.exception.UserNotExistedException;

public class AppTest {
    @Test
    public void Test() {

        // Thread t = new Thread(new MyThread());
        // t.start();
    }

    public static void main(String[] args) {
        SecurityData data = new FileSecurityData();
        
        MiniSecurity miniSecurity = new MiniSecurity(data);
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

//        try {
//            miniSecurity.signin("admin", "admin");
//            MiniLog.debug("sign in ok.");
//        } catch (UserNotExistedException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (IncorrectPasswordException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (MiniSecurityException e) {
//            MiniLog.debug(e.getMessage());
//        }
        
//        boolean result = miniSecurity.isPermittedAll("user:a","goods:a","goods:b","goods:c");
//        MiniLog.debug(String.valueOf(result));
//     
//        
//        
//        try {
//            miniSecurity.register("user01", "123", "r1","r2");
//        } catch (UserAlreadyExistedException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (MiniSecurityException e) {
//            MiniLog.debug(e.getMessage());
//        }
//
//        try {
//            miniSecurity.cancelUser("user02");
//        } catch (UnAuthenticatedException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (UserNotExistedException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (MiniSecurityException e) {
//            MiniLog.debug(e.getMessage());
//        }
//        
//        try {
//            miniSecurity.changePassword("user03", "123456");
//        } catch (UnAuthenticatedException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (UserNotExistedException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (PasswordNotChangedException e) {
//            MiniLog.debug(e.getMessage());
//        } catch (MiniSecurityException e) {
//            MiniLog.debug(e.getMessage());
//        }
    }

}