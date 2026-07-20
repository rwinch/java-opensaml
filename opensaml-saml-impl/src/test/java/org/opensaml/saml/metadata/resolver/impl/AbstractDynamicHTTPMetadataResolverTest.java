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

import java.io.ByteArrayOutputStream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSource;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.AnnotationsSupport;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.Criterion;
import net.shibboleth.shared.resolver.ResolverException;

@SuppressWarnings("javadoc")
public class AbstractDynamicHTTPMetadataResolverTest extends XMLObjectBaseTestCase {
    
    private MockDynamicHTTPMetadataResolver resolver;
    
    private HttpClientBuilder httpClientBuilder;
    
    private EntityDescriptor entityDescriptor;
    
    private byte[] entityDescriptorBytes;
    
    private boolean allowActivation;
    
    @BeforeMethod
    public void setUp() throws Exception {
        httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setConnectionDisregardTLSCertificate(true);
        
        final HttpClient httpClient = httpClientBuilder.buildClient();
        
        entityDescriptor = buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDescriptor.setEntityID("https://foo1.example.org/idp/shibboleth");
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            XMLObjectSupport.marshallToOutputStream(entityDescriptor, baos);
            entityDescriptorBytes = baos.toByteArray();
        }
        
        resolver = new MockDynamicHTTPMetadataResolver(httpClient);
        resolver.setId("myDynamicResolver");
        resolver.setParserPool(parserPool);
        resolver.setActivationCondition(prc -> {return allowActivation;});
        resolver.initialize();
        
        allowActivation = true;
    }
    
    @AfterMethod
    public void tearDown() {
        AnnotationsSupport.callOnTeardownAnnotations(resolver);
    }
    
    @Test
    public void testInactive() throws ResolverException {
        allowActivation = false;
        
        // Test uses MDQ protocol
        String baseURL = "http://mdq.incommon.org";
        String entityID = "urn:mace:incommon:osu.edu";
        String requestURL = new MetadataQueryProtocolRequestURLBuilder(baseURL).apply(new CriteriaSet(new EntityIdCriterion(entityID)));
        
        CriteriaSet criteriaSet = new CriteriaSet(new RequestURLCriterion(requestURL));
        
        EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        Assert.assertNull(ed);
    }
    
    @Test
    public void testBasicRequest() throws ResolverException {
        // Test uses MDQ protocol
        String baseURL = "http://mdq.incommon.org";
        String entityID = "urn:mace:incommon:osu.edu";
        String requestURL = new MetadataQueryProtocolRequestURLBuilder(baseURL).apply(new CriteriaSet(new EntityIdCriterion(entityID)));
        
        CriteriaSet criteriaSet = new CriteriaSet(new RequestURLCriterion(requestURL));
        
        EntityDescriptor ed = resolver.resolveSingle(criteriaSet);
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), entityID);
        Assert.assertNull(ed.getDOM());
    }
    
    @Test
    public void testResponseHandlerXMLObjectSource() throws Exception {
        HttpClientResponseHandler<XMLObject> responseHandler = resolver.new BasicMetadataResponseHandler();
        
        BasicClassicHttpResponse httpResponse = new BasicClassicHttpResponse(HttpStatus.SC_OK, "OK");
        ByteArrayEntity entity = new ByteArrayEntity(entityDescriptorBytes, ContentType.TEXT_XML);
        httpResponse.setEntity(entity);
        
        XMLObject result = responseHandler.handleResponse(httpResponse);
        Assert.assertNotNull(result);
        Assert.assertTrue(result instanceof EntityDescriptor);
        Assert.assertTrue(result.getObjectMetadata().containsKey(XMLObjectSource.class));
        Assert.assertEquals(result.getObjectMetadata().get(XMLObjectSource.class).size(), 1);
    }
    
    @Test
    public void testResponseHandlerBadStatusCode() throws Exception {
        HttpClientResponseHandler<XMLObject> responseHandler = resolver.new BasicMetadataResponseHandler();
        
        BasicClassicHttpResponse httpResponse = new BasicClassicHttpResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, "Internal Error");
        
        XMLObject result = responseHandler.handleResponse(httpResponse);
        Assert.assertNull(result);
    }
    
    @Test
    public void testResponseHandlerUnsupportedContentType() throws Exception {
        HttpClientResponseHandler<XMLObject> responseHandler = resolver.new BasicMetadataResponseHandler();
        
        BasicClassicHttpResponse httpResponse = new BasicClassicHttpResponse(HttpStatus.SC_OK, "OK");
        ByteArrayEntity entity = new ByteArrayEntity(entityDescriptorBytes, ContentType.create("application/foobar"));
        httpResponse.setEntity(entity);
        
        XMLObject result = responseHandler.handleResponse(httpResponse);
        Assert.assertNull(result);
    }
    
    
    
    // Helpers
    
    public static class MockDynamicHTTPMetadataResolver extends AbstractDynamicHTTPMetadataResolver {
        
        public MockDynamicHTTPMetadataResolver(@Nonnull HttpClient client) {
            super(null, client);
        }

        /** {@inheritDoc} */
        @Nonnull protected String buildRequestURL(@Nullable CriteriaSet criteria) {
            assert criteria != null;
            return Constraint.isNotNull(
                    criteria.get(RequestURLCriterion.class), "RequestURLCriterion was absent").requestURL;
        }
        
    }

    public static class RequestURLCriterion implements Criterion {
        public String requestURL;
        public RequestURLCriterion(String url) {
            requestURL = url;
        }
    }
    
}