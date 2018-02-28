package org.lechisoft.minifw.security;

import java.util.List;
import java.util.Map;

public interface RealmData {
	User getUser(String userName);

	List<String> getRoles(String userName);

	List<String> getPermissions(String userName);
	
	Map<String, String> getFilterChainDefinitionMap();
}
