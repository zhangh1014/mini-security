package org.lechisoft.minifw.security;

import java.util.List;

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

		return new SimpleAuthenticationInfo(user.getUserName(), user.getPassword(),
				ByteSource.Util.bytes(user.getSalt()), this.getName());
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		MiniLog.debug(MiniRealm.class.getName() + " -> "
                + Thread.currentThread().getStackTrace()[1].getMethodName() + " begin.");
		
		String userName = (String) principals.getPrimaryPrincipal();

		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
		List<String> roles = this.data.getRoles(userName);
		authorizationInfo.addRoles(roles);
		List<String> permissions = this.data.getPermissions(userName);
		authorizationInfo.addStringPermissions(permissions);
		
		for(String role :roles){
			MiniLog.debug(role);
		}
		
		for(String permission :permissions){
			MiniLog.debug(permission);
		}
		
		MiniLog.debug(MiniRealm.class.getName() + " -> "
                + Thread.currentThread().getStackTrace()[1].getMethodName() + " end.");
		return authorizationInfo;
	}

	public void setCredentialsMatcher(String hashAlgorithmName, int hashIterations) {
		// encryption strategy
		HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
		credentialsMatcher.setHashAlgorithmName(hashAlgorithmName);
		credentialsMatcher.setHashIterations(hashIterations);

		this.setCredentialsMatcher(credentialsMatcher);
	}
}
