package org.lechisoft.minifw.security;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.lechisoft.minifw.log.MiniLog;
import org.lechisoft.minifw.security.exception.SecurityDataException;
import org.lechisoft.minifw.security.model.Role;
import org.lechisoft.minifw.security.model.User;

public class MiniRealm extends AuthorizingRealm {
	private String hashAlgorithmName = "MD5";
	private int hashIterations = 1;

	RealmData data = null;

	public MiniRealm(RealmData data) {
		this.data = data;
		this.setCredentialsMatcher(this.hashAlgorithmName, this.hashIterations);
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		String userName = (String) token.getPrincipal();

		User user = this.data.getUser(userName);
		if (null == user) {
			throw new UnknownAccountException();
		}
		MiniLog.debug(user.getPassword());

		return new SimpleAuthenticationInfo(user.getUserName(), user.getPassword(),
				ByteSource.Util.bytes(user.getSalt()), this.getName());
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String userName = (String) principals.getPrimaryPrincipal();
		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();

		User user = this.data.getUser(userName);
		if (null == user) {
			throw new UnknownAccountException();
		}

		for (String roleName : user.getRoles()) {
			authorizationInfo.addRole(roleName);

			Role role = this.data.getRole(roleName);
			authorizationInfo.addStringPermissions(role.getPermissions());
		}

		return authorizationInfo;
	}

	public void setCredentialsMatcher(String hashAlgorithmName, int hashIterations) {
		// encryption strategy
		HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
		credentialsMatcher.setHashAlgorithmName(hashAlgorithmName);
		credentialsMatcher.setHashIterations(hashIterations);

		this.setCredentialsMatcher(credentialsMatcher);
	}

	public User getUser(String userName) throws SecurityDataException {
		return this.data.getUser(userName);
	}
}
