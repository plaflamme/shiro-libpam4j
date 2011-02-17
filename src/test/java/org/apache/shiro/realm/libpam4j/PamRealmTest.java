package org.apache.shiro.realm.libpam4j;

import static org.junit.Assume.assumeTrue;
import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.notNullValue;

import java.io.File;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.junit.Ignore;
import org.junit.Test;

public class PamRealmTest {

	@Test
	public void test_initDoesNotThrowException() {
		assumeTrue(new File("/etc/pam.d/common-auth").exists());
		PamRealm r = new PamRealm();
		r.setService("common-auth");
		r.init();
	}

	@Test(expected=AuthenticationException.class)
	public  void test_invalidCredentials() {
		assumeTrue(new File("/etc/pam.d/common-auth").exists());
		PamRealm r = new PamRealm();
		r.setService("common-auth");
		AuthenticationInfo info = r.doGetAuthenticationInfo(new UsernamePasswordToken("username", "pasword"));
	}

	@Test
	@Ignore("can only test authentication with valid credentials")
	public  void test_authenticationSuccessful() {
		assumeTrue(new File("/etc/pam.d/common-auth").exists());
		PamRealm r = new PamRealm();
		r.setService("common-auth");

		AuthenticationInfo info = r.doGetAuthenticationInfo(new UsernamePasswordToken("username", "pasword"));
		assertThat(info.getPrincipals().getPrimaryPrincipal(), notNullValue());
	}

}
