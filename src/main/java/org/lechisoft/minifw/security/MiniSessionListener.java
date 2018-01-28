package org.lechisoft.minifw.security;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListenerAdapter;
import org.lechisoft.minifw.log.MiniLog;

public class MiniSessionListener extends SessionListenerAdapter {
	@Override
	public void onStart(Session session) {
		MiniLog.debug("会话创建：" + session.getId());
	}
}
