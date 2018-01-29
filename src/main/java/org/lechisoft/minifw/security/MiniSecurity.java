package org.lechisoft.minifw.security;

import java.util.Arrays;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

public class MiniSecurity {

	private Subject getSubject() {
		return SecurityUtils.getSubject();
	}

	public Session getSession() {
		return this.getSubject().getSession();
	}

	public boolean isAuthenticated() {
		return this.getSubject().isAuthenticated();
	}

	public void signin(String userName, String password)
			throws UnknownAccountException, IncorrectCredentialsException, AuthenticationException {
		this.signin(userName, password, false);
	}

	public void signin(String userName, String password, boolean rememberMe)
			throws UnknownAccountException, IncorrectCredentialsException, AuthenticationException {
		UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
		token.setRememberMe(rememberMe);
		this.getSubject().login(token);
	}

	public void signout() {
		this.getSubject().logout();
	}

	public boolean isPermitted(String permission) {
		Subject subject = this.getSubject();
		return subject.isPermitted(permission);
	}

	public boolean isPermittedAll(String... permissions) {
		Subject subject = this.getSubject();
		return subject.isPermittedAll(permissions);
	}

	public boolean isPermittedAny(String... permissions) {
		Subject subject = this.getSubject();
		for (String permission : permissions) {
			if (subject.isPermitted(permission)) {
				return true;
			}
		}
		return false;
	}

	public boolean hasRole(String role) {
		Subject subject = this.getSubject();
		return subject.hasRole(role);
	}

	public boolean hasAllRoles(String... roles) {
		Subject subject = this.getSubject();
		return subject.hasAllRoles(Arrays.asList(roles));
	}

	public boolean hasAnyRole(String... roles) {
		Subject subject = this.getSubject();
		for (String role : roles) {
			if (subject.hasRole(role)) {
				return true;
			}
		}
		return false;
	}
}
