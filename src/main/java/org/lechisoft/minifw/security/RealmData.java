package org.lechisoft.minifw.security;

import java.util.List;
import java.util.Map;

public interface RealmData {
	/**
	 * 获取用户
	 * @param userName 用户名
	 * @return 用户对象
	 */
	User getUser(String userName);

	/**
	 * 获取用户的角色
	 * @param userName 用户名
	 * @return 角色列表
	 */
	List<String> getRoles(String userName);

	/**
	 * 获取用户的权限
	 * @param userName 用户名
	 * @return 权限列表
	 */
	List<String> getPermissions(String userName);
	
	/**
	 * 获取对URL过滤的过滤链定义
	 * @return Map对象
	 */
	Map<String, String> getFilterChainDefinitionMap();
}
