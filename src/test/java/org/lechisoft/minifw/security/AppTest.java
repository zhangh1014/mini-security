package org.lechisoft.minifw.security;

import org.junit.Test;

public class AppTest
{
   @Test
   public void Test(){
       MiniSecurity miniSecurity = new MiniSecurity();
       miniSecurity.login("admin", "admin");
       
       miniSecurity.reload();
   }
}
