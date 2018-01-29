package org.lechisoft.minifw.security;

import java.util.List;

public interface RealmData {
	User getUser(String userName);

	List<String> getRoles(String userName);

	List<String> getPermissions(String userName);
}
