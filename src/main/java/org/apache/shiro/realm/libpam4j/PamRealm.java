/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm.libpam4j;

import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;

/**
 * A Unix-style <a href="http://www.kernel.org/pub/linux/libs/pam/index.html">PAM</a> 
 * {@link org.apache.shiro.realm.Realm Realm} that uses <a href="https://github.com/kohsuke/libpam4j">libpam4j</a>
 * to interface with the PAM system libraries.
 * <p>
 * This is a single Shiro {@code Realm} that interfaces with the OS's {@code PAM} subsystem which itself
 * can be connected to several authentication methods (unix-crypt, LDAP, etc.)
 * <p>
 * This {@code Realm} can also take part in Shiro's Pluggable Realms concept.
 * <p>
 * Using a {@code PamRealm} requires a PAM {@code service} name. This is the name of the file under
 * {@code /etc/pam.d} that is used to initialise and configure the PAM subsytem. Normally, this file reflects
 * the application using it. For example {@code gdm}, {@code su}, etc. There is no default value for this propery.
 * <p>
 * For example, defining this realm in Shiro .ini:
 * <pre>
 * [main]
 * pamRealm = org.apache.shiro.realm.libpam4j.PamRealm
 * pamRealm.service = my-app
 * </pre>
 * 
 * @author philippe.laflamme@gmail.com
 */
public class PamRealm extends AuthorizingRealm {

	private String service;

	public void setService(String service) {
		this.service = service;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		Set<String> roles = new LinkedHashSet<String>();

		UnixUserPrincipal user = principals.oneByType(UnixUserPrincipal.class);
		if (user != null) {
			roles.addAll(user.getUnixUser().getGroups());
		}
		return new SimpleAuthorizationInfo(roles);
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		UnixUser user;
		try {
			user = getPam().authenticate(upToken.getUsername(),
					new String(upToken.getPassword()));
		} catch (PAMException e) {
			throw new AuthenticationException(e);
		}
		return new SimpleAuthenticationInfo(new UnixUserPrincipal(user), upToken.getPassword(),
				getName());
	}

	@Override
	protected void onInit() {
		super.onInit();
		try {
			// Tests PAM "connectivity"
			getPam();
		} catch (PAMException e) {
			throw new RuntimeException(e);
		}
	}

	protected PAM getPam() throws PAMException {
		return new PAM(service);
	}

	private static class UnixUserPrincipal {

		private final UnixUser unixUser;
		UnixUserPrincipal(UnixUser unixUser) {
			this.unixUser = unixUser;
		}
		
		public UnixUser getUnixUser() {
			return unixUser;
		}
		
		@Override
		public String toString() {
			return unixUser.getUserName() + ":" + unixUser.getUID();
		}
	}
}
