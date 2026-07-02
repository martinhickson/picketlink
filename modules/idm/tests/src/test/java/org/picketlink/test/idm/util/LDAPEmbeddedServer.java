/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.picketlink.test.idm.util;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldif.LDIFReader;

import java.io.InputStream;
import java.util.Properties;

/**
 * Embedded LDAP server for IDM tests, backed by the UnboundID in-memory directory server.
 */
public class LDAPEmbeddedServer {

    public static final String BASE_DN = "dc=jboss,dc=org";
    public static final String LDAP_URL = "ldap://localhost:10389";
    public static final String ROLES_DN_SUFFIX = "ou=Roles,dc=jboss,dc=org";
    public static final String GROUP_DN_SUFFIX = "ou=Groups,dc=jboss,dc=org";
    public static final String USER_DN_SUFFIX = "ou=People,dc=jboss,dc=org";
    public static final String AGENT_DN_SUFFIX = "ou=Agent,dc=jboss,dc=org";
    public static final String CUSTOM_ACCOUNT_DN_SUFFIX = "ou=CustomAccount,dc=jboss,dc=org";

    public static final String CONNECTION_PROPERTIES = "config/ldap-connection.properties";
    public static final String OPERATIONAL_CREATE_TIMESTAMP = "createTimestamp";
    public static final String OPERATIONAL_MODIFY_TIMESTAMP = "modifyTimestamp";

    protected String connectionUrl = LDAP_URL;
    protected String baseDn = BASE_DN;
    protected String userDnSuffix = USER_DN_SUFFIX;
    protected String rolesDnSuffix = ROLES_DN_SUFFIX;
    protected String groupDnSuffix = GROUP_DN_SUFFIX;
    protected String agentDnSuffix = AGENT_DN_SUFFIX;
    protected boolean startEmbeddedLdapLerver = true;
    protected String bindDn = "uid=admin,ou=system,dc=jboss,dc=org";
    protected String bindCredential = "secret";

    public static String IDM_TEST_LDAP_CONNECTION_URL = "idm.test.ldap.connection.url";
    public static String IDM_TEST_LDAP_BASE_DN = "idm.test.ldap.base.dn";
    public static String IDM_TEST_LDAP_ROLES_DN_SUFFIX = "idm.test.ldap.roles.dn.suffix";
    public static String IDM_TEST_LDAP_GROUP_DN_SUFFIX = "idm.test.ldap.group.dn.suffix";
    public static String IDM_TEST_LDAP_USER_DN_SUFFIX = "idm.test.ldap.user.dn.suffix";
    public static String IDM_TEST_LDAP_AGENT_DN_SUFFIX = "idm.test.ldap.agent.dn.suffix";
    public static String IDM_TEST_LDAP_START_EMBEDDED_LDAP_SERVER = "idm.test.ldap.start.embedded.ldap.server";
    public static String IDM_TEST_LDAP_BIND_DN = "idm.test.ldap.bind.dn";
    public static String IDM_TEST_LDAP_BIND_CREDENTIAL = "idm.test.ldap.bind.credential";

    private InMemoryDirectoryServer directoryServer;

    public LDAPEmbeddedServer() {
        loadConnectionProperties();
    }

    protected void loadConnectionProperties() {
        Properties p = new Properties();
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(CONNECTION_PROPERTIES)) {
            p.load(is);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        connectionUrl = p.getProperty(IDM_TEST_LDAP_CONNECTION_URL, LDAP_URL);
        baseDn = p.getProperty(IDM_TEST_LDAP_BASE_DN, BASE_DN);
        userDnSuffix = p.getProperty(IDM_TEST_LDAP_USER_DN_SUFFIX, USER_DN_SUFFIX);
        rolesDnSuffix = p.getProperty(IDM_TEST_LDAP_ROLES_DN_SUFFIX, ROLES_DN_SUFFIX);
        groupDnSuffix = p.getProperty(IDM_TEST_LDAP_GROUP_DN_SUFFIX, GROUP_DN_SUFFIX);
        agentDnSuffix = p.getProperty(IDM_TEST_LDAP_AGENT_DN_SUFFIX, AGENT_DN_SUFFIX);
        startEmbeddedLdapLerver = Boolean.parseBoolean(p.getProperty(IDM_TEST_LDAP_START_EMBEDDED_LDAP_SERVER, "true"));
        bindDn = p.getProperty(IDM_TEST_LDAP_BIND_DN, bindDn);
        bindCredential = p.getProperty(IDM_TEST_LDAP_BIND_CREDENTIAL, bindCredential);
    }

    public void setup() throws Exception {
        if (!isStartEmbeddedLdapLerver()) {
            return;
        }

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(baseDn);
        config.addAdditionalBindCredentials(getFullBindDn(), bindCredential);

        int port = parsePort(connectionUrl);
        config.setListenerConfigs(new InMemoryListenerConfig("ldap", null, port, null, null, null));

        this.directoryServer = new InMemoryDirectoryServer(config);
        this.directoryServer.startListening();
    }

    public void tearDown() throws Exception {
        if (this.directoryServer != null) {
            this.directoryServer.shutDown(true);
            this.directoryServer = null;
        }
    }

    public void importLDIF(String fileName) throws Exception {
        if (!isStartEmbeddedLdapLerver() || this.directoryServer == null) {
            return;
        }

        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        if (is == null) {
            throw new IllegalArgumentException("LDIF resource not found: " + fileName);
        }
        try (InputStream ldifStream = is; LDIFReader reader = new LDIFReader(ldifStream)) {
            this.directoryServer.importFromLDIF(true, reader);
        }
    }

    private String getFullBindDn() {
        if (bindDn.toLowerCase().contains("dc=")) {
            return bindDn;
        }
        return bindDn + "," + baseDn;
    }

    private static int parsePort(String url) {
        int schemeEnd = url.indexOf("://");
        int portStart = url.lastIndexOf(':');
        if (schemeEnd >= 0 && portStart > schemeEnd + 2) {
            return Integer.parseInt(url.substring(portStart + 1));
        }
        return 389;
    }

    public String getConnectionUrl() {
        return connectionUrl;
    }

    public String getBaseDn() {
        return baseDn;
    }

    public String getUserDnSuffix() {
        return userDnSuffix;
    }

    public String getRolesDnSuffix() {
        return rolesDnSuffix;
    }

    public String getGroupDnSuffix() {
        return groupDnSuffix;
    }

    public String getAgentDnSuffix() {
        return agentDnSuffix;
    }

    public boolean isStartEmbeddedLdapLerver() {
        return startEmbeddedLdapLerver;
    }

    public String getBindDn() {
        return bindDn;
    }

    public String getBindCredential() {
        return bindCredential;
    }
}
