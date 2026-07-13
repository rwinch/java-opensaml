/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.saml.metadata.resolver.filter.impl;

import java.time.Duration;
import java.util.ArrayList;

import javax.xml.namespace.QName;

import org.apache.hc.client5.http.classic.HttpClient;
import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolverTest;
import org.opensaml.saml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.springframework.core.io.ClassPathResource;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.spring.resource.ResourceHelper;
import net.shibboleth.shared.testing.EmbeddedJetty;

/**
 * Unit tests for {@link EntityRoleFilter}.
 */
@SuppressWarnings("javadoc")
public class EntityRoleFilterTest extends XMLObjectBaseTestCase {

    private EmbeddedJetty jetty;
    
    private HttpClient httpClient;

    private HttpClientBuilder httpClientBuilder;

    private HTTPMetadataResolver metadataProvider;
    
    private HttpClientSecurityParameters httpClientParams;

    /** URL to InCommon metadata. */
    private String inCommonMDURL;
    
    @BeforeClass
    protected void setUpClass() throws Exception {
        jetty = new EmbeddedJetty();
        jetty.startServer(new EmbeddedJetty.ResourceHandler(200,
                ResourceHelper.of(new ClassPathResource("org/opensaml/saml/saml2/metadata/InCommon-metadata.xml"))));
        
        inCommonMDURL = "https://localhost:8443/InCommon-metadata.xml";
        
        httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setConnectionTimeout(Duration.ofSeconds(5));
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        httpClient = httpClientBuilder.buildClient();

        httpClientParams = new HttpClientSecurityParameters();
        httpClientParams.setTLSTrustEngine(HTTPMetadataResolverTest.buildExplicitKeyTrustEngine(EmbeddedJetty.getServerCertficateResource()));
    }
    
    @AfterClass
    protected void tearDownClass() {
        if (jetty != null) {
            jetty.stopServer();
            jetty = null;
        }
    }

    @BeforeMethod
    protected void setUpMethod() throws Exception {
        metadataProvider = new HTTPMetadataResolver(httpClient, inCommonMDURL);
        metadataProvider.setHttpClientSecurityParameters(httpClientParams);
    }

    @Test
    public void testWhiteListSPRole() throws Exception {
        final ArrayList<QName> retainedRoles = new ArrayList<>();
        retainedRoles.add(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        final EntityRoleFilter filter = new EntityRoleFilter(retainedRoles);
        filter.initialize();
        
        metadataProvider.setMetadataFilter(filter);
        metadataProvider.setParserPool(parserPool);
        metadataProvider.setId("test");
        metadataProvider.initialize();
    }
    
    @Test
    public void testWhiteListIdPRoles() throws Exception {
        final ArrayList<QName> retainedRoles = new ArrayList<>();
        retainedRoles.add(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        retainedRoles.add(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);

        final EntityRoleFilter filter = new EntityRoleFilter(retainedRoles);
        filter.initialize();
        
        metadataProvider.setMetadataFilter(filter);
        metadataProvider.setParserPool(parserPool);
        metadataProvider.setId("test");
        metadataProvider.initialize();
    }
    
    @Test
    public void testWhiteListNoRole() throws Exception {
        final ArrayList<QName> retainedRoles = new ArrayList<>();
        final EntityRoleFilter filter = new EntityRoleFilter(retainedRoles);
        filter.initialize();
        
        metadataProvider.setMetadataFilter(filter);
        metadataProvider.setParserPool(parserPool);
        metadataProvider.setId("test");
        metadataProvider.initialize();
    }
}