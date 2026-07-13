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

package org.opensaml.saml.metadata.resolver.impl;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.annotation.Nonnull;


import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.saml.common.binding.artifact.SAMLSourceIDArtifact;
import org.opensaml.saml.criterion.ArtifactCriterion;
import org.opensaml.saml.metadata.resolver.impl.TemplateRequestURLBuilder.EncodingStyle;
import org.opensaml.saml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.springframework.core.io.ClassPathResource;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Predicates;
import com.google.common.io.Resources;

import net.shibboleth.shared.codec.StringDigester;
import net.shibboleth.shared.codec.StringDigester.OutputFormat;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.primitive.NonnullSupplier;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resource.Resource;
import net.shibboleth.shared.spring.resource.ResourceHelper;
import net.shibboleth.shared.testing.EmbeddedJetty;
import net.shibboleth.shared.testing.VelocityEngine;

@SuppressWarnings("javadoc")
public class FunctionDrivenDynamicHTTPMetadataResolverTest extends XMLObjectBaseTestCase {
    
    private EmbeddedJetty jetty;
    private int jettyStatus;
    private String keystorePath;

    private Resource relativeMDResource;
    
    private FunctionDrivenDynamicHTTPMetadataResolver resolver;
    
    private HttpClientBuilder httpClientBuilder;
    
    @BeforeClass
    public void startJetty() throws FileNotFoundException, IOException {
        
        relativeMDResource = ResourceHelper.of(new ClassPathResource("org/opensaml/saml/metadata/resolver/impl/localhost-sp.xml"));

        // Copy Jetty keystore from jar classpath to file system for Java system property testing.
        keystorePath = System.getProperty("java.io.tmpdir") + System.getProperty("file.separator") + "localhost-keystore.p12";
        try (final FileOutputStream keystoreStream = new FileOutputStream(keystorePath)) {
            Resources.copy(EmbeddedJetty.getServerKeystoreResource().getURL(), keystoreStream);
        }

        jetty = new EmbeddedJetty();
        final var handler = new EmbeddedJetty.ResourceHandler(
                new NonnullSupplier<Integer>() {
                    @Nonnull public Integer get() {
                        return jettyStatus;
                    }
                },
                NonnullSupplier.of(relativeMDResource)
                ); 
        handler.setContentType("text/xml");
        jetty.startServer(handler);
    }
    
    @AfterClass
    public void stopJetty() throws IOException {
        if (jetty != null) {
            jetty.stopServer();
            jetty = null;
        }
        
        Files.delete(Path.of(keystorePath));
    }
    
    @BeforeMethod
    public void setUp() {
        jettyStatus = 200;
        httpClientBuilder = new HttpClientBuilder();
    }
    
    @AfterMethod
    public void tearDown() {
        if (resolver != null) {
            resolver.destroy();
        }
    }
    
    
    @Test
    public void testInactive() throws Exception {
        // Repo should return 'text/xml', which is supported by default.
        final String template = "http://localhost:8080/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.setActivationCondition(Predicates.alwaysFalse());
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testTemplateFromRepoDefaultContentTypes() throws Exception {
        // Jetty should return 'text/xml', which is supported by default.
        final String template = "http://localhost:8080/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }

    @Test
    public void testTemplateFromRepoUnsupportedContentType() throws Exception {
        // Repo should return 'text/plain', which is not supported by default.
        final String template = "http://localhost:8080/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.setSupportedContentTypes(Arrays.asList("application/samlmetadata+xml", "application/xml"));
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testTemplateNonexistentDomain() throws Exception {
        // Unresolveable domain.  Should silently fail.
        final String template = "http://bogus.example.org/metadata?entityID=${entityID}";
        final String entityID = "https://localhost:8443/sp";
        
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.form);
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testTemplateNonexistentPath() throws Exception {
        jettyStatus = 404;
        
        final String template = "http://localhost:8080/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.form);
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testWellKnownLocation() throws Exception {
        final String entityID = "https://localhost:8443/sp";
        
        final HTTPEntityIDRequestURLBuilder requestURLBuilder = new HTTPEntityIDRequestURLBuilder();
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        
        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildExplicitKeyTrustEngine(EmbeddedJetty.getServerCertficateResource()));
        resolver.setHttpClientSecurityParameters(params);
        
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testMDQ() throws Exception {
        final String baseURL = "http://mdq.incommon.org";
        final String entityID = "urn:mace:incommon:osu.edu";
        
        final MetadataQueryProtocolRequestURLBuilder requestURLBuilder = new MetadataQueryProtocolRequestURLBuilder(baseURL);
        
        httpClientBuilder.setConnectionDisregardTLSCertificate(true);
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testMDQViaArtifact() throws Exception {
        final String baseURL = "http://mdq.incommon.org";
        final String entityID = "urn:mace:incommon:osu.edu";
        
        final MetadataQueryProtocolRequestURLBuilder requestURLBuilder = new MetadataQueryProtocolRequestURLBuilder(baseURL,
                CollectionSupport.singletonList(new SAMLArtifactURLBuilder()));
        
        httpClientBuilder.setConnectionDisregardTLSCertificate(true);
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.initialize();
        
        final MessageDigest sha1Digester = MessageDigest.getInstance(JCAConstants.DIGEST_SHA1);
        byte[] entityIDSourceID = sha1Digester.digest(entityID.getBytes("UTF-8"));
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] messageHandle = new byte[20];
        secureRandom.nextBytes(messageHandle);
        final SAMLSourceIDArtifact sourceIDArtifact = new SAML2ArtifactType0004(new byte[] {0, 0} , entityIDSourceID, messageHandle);
        
        final CriteriaSet criteriaSet = new CriteriaSet( new ArtifactCriterion(sourceIDArtifact));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testTrustEngineSocketFactoryNoHTTPSNoTrustEngine() throws Exception {
        final String template = "http://localhost:8080/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testTrustEngineSocketFactoryNoHTTPSWithTrustEngine() throws Exception  {
        final String template = "http://localhost:8080/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildExplicitKeyTrustEngine(EmbeddedJetty.getServerCertficateResource()));
        resolver.setHttpClientSecurityParameters(params);

        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testHTTPSNoTrustEngine() throws Exception  {
        try {
            System.setProperty("javax.net.ssl.trustStore", keystorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", EmbeddedJetty.getServerKeystorePassword());
            
            final String template = "https://localhost:8443/entities/${entityID}.xml";
            final String entityID = "https://localhost:8443/sp";

            // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
            final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                    VelocityEngine.newVelocityEngine(), 
                    template, 
                    EncodingStyle.path, 
                    new StringDigester("SHA-1", OutputFormat.HEX_LOWER));

            httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory(false));

            resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
            resolver.setId("myDynamicResolver");
            resolver.setParserPool(parserPool);
            resolver.setRequestURLBuilder(requestURLBuilder);
            resolver.initialize();

            final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));

            final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
            assert ed != null;
            Assert.assertEquals(ed.getEntityID(), entityID);
            Assert.assertNull(ed.getDOM());
        } finally {
            System.setProperty("javax.net.ssl.trustStore", "");
            System.setProperty("javax.net.ssl.trustStorePassword", "");
        }
    }
    
    @Test
    public void testHTTPSTrustEngineExplicitKey() throws Exception  {
        final String template = "https://localhost:8443/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildExplicitKeyTrustEngine(EmbeddedJetty.getServerCertficateResource()));
        resolver.setHttpClientSecurityParameters(params);
        
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testHTTPSTrustEngineInvalidKey()  throws Exception {
        final String template = "https://localhost:8443/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildExplicitKeyTrustEngine(
                ResourceHelper.of(new ClassPathResource(HTTPMetadataResolverTest.DATA_PATH + "badKey.crt"))));
        resolver.setHttpClientSecurityParameters(params);
        
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testHTTPSTrustEngineValidPKIX() throws Exception  {
        final String template = "https://localhost:8443/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildPKIXTrustEngine(EmbeddedJetty.getServerCertficateResource(), null, false));
        resolver.setHttpClientSecurityParameters(params);
        
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testHTTPSTrustEngineValidPKIXExplicitName() throws Exception  {
        final String template = "https://localhost:8443/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildPKIXTrustEngine(EmbeddedJetty.getServerCertficateResource(), "localhost", true));
        resolver.setHttpClientSecurityParameters(params);
        
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testHTTPSTrustEngineInvalidPKIX() throws Exception  {
        final String template = "https://localhost:8443/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildPKIXTrustEngine(
                ResourceHelper.of(new ClassPathResource(HTTPMetadataResolverTest.DATA_PATH + "badKey.crt")), null, false));
        resolver.setHttpClientSecurityParameters(params);
        
        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testHTTPSTrustEngineValidPKIXInvalidName() throws Exception  {
        final String template = "https://localhost:8443/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        httpClientBuilder.setTLSSocketFactory(HTTPMetadataResolverTest.buildSocketFactory());
        
        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildPKIXTrustEngine(EmbeddedJetty.getServerCertficateResource(), "localhostbad", true));
        resolver.setHttpClientSecurityParameters(params);

        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testHTTPSTrustEngineWrongSocketFactory() throws Exception  {
        final String template = "https://localhost:8443/entities/${entityID}.xml";
        final String entityID = "https://localhost:8443/sp";
        
        // Digesting the entityID is a little artificial for the test, but means we can test more easily against a path in the repo.
        final TemplateRequestURLBuilder requestURLBuilder = new TemplateRequestURLBuilder(
                VelocityEngine.newVelocityEngine(), 
                template, 
                EncodingStyle.path, 
                new StringDigester("SHA-1", OutputFormat.HEX_LOWER));
        
        // Trust engine set, but appropriate socket factory not set

        resolver = new FunctionDrivenDynamicHTTPMetadataResolver(httpClientBuilder.buildClient());
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setRequestURLBuilder(requestURLBuilder);

        final HttpClientSecurityParameters params = new HttpClientSecurityParameters();
        params.setTLSTrustEngine(HTTPMetadataResolverTest.buildExplicitKeyTrustEngine(EmbeddedJetty.getServerCertficateResource()));
        resolver.setHttpClientSecurityParameters(params);

        resolver.initialize();
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIdCriterion(entityID));
        
        final EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
}