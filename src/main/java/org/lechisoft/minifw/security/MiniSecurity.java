package org.lechisoft.minifw.security;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.lechisoft.minifw.log.MiniLog;

public class MiniSecurity {

	public static Subject getSubject() {
		return SecurityUtils.getSubject();
	}

	public static Session getSession() {
		return MiniSecurity.getSubject().getSession();
	}

	public static String getSessionId() {
		return MiniSecurity.getSubject().getSession().getId().toString();
	}

	public static Object getSessionAttribute(Object key) {
		return MiniSecurity.getSubject().getSession().getAttribute(key);
	}

	public static String getHash(String algorithmName, Object source) {
		return MiniSecurity.getHash(algorithmName, source, "", 1);
	}

	public static String getHash(String algorithmName, Object source, Object salt) {
		return MiniSecurity.getHash(algorithmName, source, salt, 1);
	}

	public static String getHash(String algorithmName, Object source, Object salt, int hashIterations) {
		return new SimpleHash(algorithmName, source, salt, hashIterations).toString();
	}

	public static void setSessionAttribute(Object key, Object value) {
		MiniSecurity.getSubject().getSession().setAttribute(key, value);
	}

	public static boolean isAuthenticated() {
		return MiniSecurity.getSubject().isAuthenticated();
	}

	public static void signin(String userName, String password)
			throws UnknownAccountException, IncorrectCredentialsException, AuthenticationException {
		MiniSecurity.signin(userName, password, false);
	}

	public static void signin(String userName, String password, boolean rememberMe)
			throws UnknownAccountException, IncorrectCredentialsException, AuthenticationException {
		UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
		token.setRememberMe(rememberMe);
		MiniSecurity.getSubject().login(token);
	}

	public static void signout() {
		MiniSecurity.getSubject().logout();
	}

	public static Map<String, String> getFilterChainDefinitionMap() {
		return MiniSecurity.getFilterChainDefinitionMap("/shiroFilterChain.properties");
	}

	public static Map<String, String> getFilterChainDefinitionMap(String path) {
		Map<String, String> filterChainDefinitionMap = new HashMap<String, String>();
		InputStream is = MiniSecurity.class.getClassLoader().getResourceAsStream(path);

		try {
			Properties props = new OrderProperties();
			props.load(is);
			for (String key : props.stringPropertyNames()) {
				String val = props.getProperty(key);
				filterChainDefinitionMap.put(key, val);
				MiniLog.debug(key+"="+val);
			}
		} catch (IOException e) {
			MiniLog.error("load " + path + " error.");
		}
		return filterChainDefinitionMap;
	}

	public static boolean isPermitted(String permission) {
		Subject subject = MiniSecurity.getSubject();
		return subject.isPermitted(permission);
	}

	public static boolean isPermittedAll(String... permissions) {
		Subject subject = MiniSecurity.getSubject();
		return subject.isPermittedAll(permissions);
	}

	public static boolean isPermittedAny(String... permissions) {
		Subject subject = MiniSecurity.getSubject();
		for (String permission : permissions) {
			if (subject.isPermitted(permission)) {
				return true;
			}
		}
		return false;
	}

	public static boolean hasRole(String role) {
		Subject subject = MiniSecurity.getSubject();
		return subject.hasRole(role);
	}

	public static boolean hasAllRoles(String... roles) {
		Subject subject = MiniSecurity.getSubject();
		return subject.hasAllRoles(Arrays.asList(roles));
	}

	public static boolean hasAnyRole(String... roles) {
		Subject subject = MiniSecurity.getSubject();
		for (String role : roles) {
			if (subject.hasRole(role)) {
				return true;
			}
		}
		return false;
	}
}
