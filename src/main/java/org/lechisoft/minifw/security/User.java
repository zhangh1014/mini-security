package org.lechisoft.minifw.security;

public class User implements Cloneable {

	private String userName = ""; // user name
	private String password = ""; // password
	private String salt = ""; // salt

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}
}