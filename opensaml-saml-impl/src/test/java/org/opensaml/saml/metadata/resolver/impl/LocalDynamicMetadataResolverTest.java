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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import javax.annotation.Nonnull;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.persist.MapLoadSaveManager;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.crypto.JCAConstants;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.util.concurrent.Uninterruptibles;

import net.shibboleth.shared.codec.StringDigester;
import net.shibboleth.shared.codec.StringDigester.OutputFormat;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.PredicateSupport;
import net.shibboleth.shared.primitive.AnnotationsSupport;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * Unit test for {@link LocalDynamicMetadataResolver}.
 */
@SuppressWarnings("javadoc")
public class LocalDynamicMetadataResolverTest extends XMLObjectBaseTestCase {
    
    private LocalDynamicMetadataResolver resolver;
    
    private MapLoadSaveManager<XMLObject> sourceManager;
    
    private String entityID1, entityID2;
    
    private EntityDescriptor entity1, entity2;
    
    private StringDigester sha1Digester;
    
    @BeforeMethod
    public void setUp() throws NoSuchAlgorithmException, ComponentInitializationException {
        sha1Digester = new StringDigester(JCAConstants.DIGEST_SHA1, OutputFormat.HEX_LOWER);
        
        sourceManager = new MapLoadSaveManager<>();
        
        entityID1 = "urn:test:entity1";
        entityID2 = "urn:test:entity2";
        
        entity1 = buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entity1.setEntityID(entityID1);
        entity2 = buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entity2.setEntityID(entityID2);
        
        resolver = new LocalDynamicMetadataResolver(sourceManager);
        resolver.setId("abc123");
        resolver.setParserPool(parserPool);
        // Setting this sort so can wait past it in order to test certain things 
        resolver.setNegativeLookupCacheDuration(Duration.ofSeconds(1));
        resolver.initialize();
    }
    
    @AfterMethod
    public void tearDown() {
        AnnotationsSupport.callOnTeardownAnnotations(resolver);
    }
    
    @Test
    public void testInactive() throws ComponentInitializationException, IOException, ResolverException {
        
        resolver = new LocalDynamicMetadataResolver(null, sourceManager, new IdentityEntityIDGenerator());
        resolver.setId("abc123");
        resolver.setParserPool(parserPool);
        resolver.setActivationCondition(PredicateSupport.alwaysFalse());
        resolver.initialize();
        
        sourceManager.save(entityID1, entity1);
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))));
    }
    
    @Test
    public void testEmptySource() throws ResolverException {
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))));
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID2))));
    }

    @Test
    public void testBasicResolveLifecycle() throws ResolverException, IOException {
        sourceManager.save(sha1Digester(entityID1), entity1);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))), entity1);
        
        // Not there yet
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID2))));
        
        // Add it
        sourceManager.save(sha1Digester(entityID2), entity2);
        
        // Wait for the negative lookup cache to expire
        Uninterruptibles.sleepUninterruptibly(resolver.getNegativeLookupCacheDuration().toMillis()+150, TimeUnit.MILLISECONDS);
        
        // Now should be resolveable
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID2))), entity2);
        
        // Remove source data
        sourceManager.remove(sha1Digester(entityID1));
        sourceManager.remove(sha1Digester(entityID2));
        Assert.assertNull(sourceManager.load(sha1Digester(entityID1)));
        Assert.assertNull(sourceManager.load(sha1Digester(entityID2)));
        
        // Should still be live b/c already resolved
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))), entity1);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID2))), entity2);
    }
    
    @Test
    public void testConditionalLoadManagerWithClearEntityID() throws IOException, ResolverException, ComponentInitializationException {
        sourceManager = new MapLoadSaveManager<>(true);
        resolver = new LocalDynamicMetadataResolver(sourceManager);
        resolver.setId("abc123");
        resolver.setParserPool(parserPool);
        resolver.initialize();
        
        sourceManager.save(sha1Digester(entityID1), entity1);
        
        // This will resolve from source manager directly
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))), entity1);
        
        // This will be from in-memory cache
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))), entity1);
        
        // Clear from in-memory cache
        resolver.clear(entityID1);
        Assert.assertNull(resolver.ensureBackingStore().getIndexedDescriptors().get(entityID1));
        Assert.assertFalse(resolver.ensureBackingStore().getOrderedDescriptors().contains(entity1));
        
        // This should re-resolve from source manager directly
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))), entity1);
        
        // This will be from in-memory cache (again)
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))), entity1);
        
    }

    @Test
    public void testCtorSourceKeyGenerator() throws ComponentInitializationException, IOException, ResolverException {
        AnnotationsSupport.callOnTeardownAnnotations(resolver);
        
        resolver = new LocalDynamicMetadataResolver(null, sourceManager, new IdentityEntityIDGenerator());
        resolver.setId("abc123");
        resolver.setParserPool(parserPool);
        resolver.initialize();
        
        sourceManager.save(entityID1, entity1);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID1))), entity1);
    }
    
    @Nonnull private String sha1Digester(@Nonnull final String input) {
        final String sha1 = sha1Digester.apply(input);
        if (sha1 == null) {
            throw new IllegalStateException("Digest was null");
        }
        return sha1;
    }
    
}