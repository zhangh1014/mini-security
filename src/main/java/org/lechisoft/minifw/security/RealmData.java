package org.lechisoft.minifw.security;

import org.lechisoft.minifw.security.model.Role;
import org.lechisoft.minifw.security.model.User;

public interface RealmData {
	User getUser(String userName);
	Role getRole(String roleName);
}
