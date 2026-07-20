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
import java.io.IOException;
import java.security.KeyPair;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.Timer;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.annotation.Nullable;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.persist.MapLoadSaveManager;
import org.opensaml.core.xml.persist.XMLObjectLoadSaveManager;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import org.opensaml.saml.metadata.resolver.impl.AbstractDynamicMetadataResolver.DynamicEntityBackingStore;
import org.opensaml.saml.metadata.resolver.index.MetadataIndex;
import org.opensaml.saml.metadata.resolver.index.impl.FunctionDrivenMetadataIndex;
import org.opensaml.saml.metadata.resolver.index.impl.RoleMetadataIndex;
import org.opensaml.saml.metadata.resolver.index.impl.SimpleStringCriteriaFunction;
import org.opensaml.saml.metadata.resolver.index.impl.SimpleStringCriterion;
import org.opensaml.saml.metadata.resolver.index.impl.UppercaseEntityIdDescriptorFunction;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.Iterables;

import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.AnnotationsSupport;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;

@SuppressWarnings("javadoc")
public class AbstractDynamicMetadataResolverTest extends XMLObjectBaseTestCase {
    
    private Map<String, EntityDescriptor> sourceMap;
    
    private XMLObjectLoadSaveManager<EntityDescriptor> persistentCacheManager;
    private Map<String,EntityDescriptor> persistentCacheMap;
    private Function<EntityDescriptor, String> persistentCacheKeyGenerator;
    
    private MockDynamicResolver resolver;
    
    private String id1, id2, id3;
    private EntityDescriptor ed1, ed2, ed3;
    
    private Credential signingCred;
    private SignatureSigningParameters signingParams;
    private SignatureTrustEngine signatureTrustEngine;
    private SignatureValidationFilter signatureValidationFilter;
    
    private boolean allowActivation;
    
    @BeforeClass
    protected void setUpSigningSupport() throws Exception {
        KeyPair kp = KeySupport.generateKeyPair(JCAConstants.KEY_ALGO_RSA, 1024, null);
        signingCred = CredentialSupport.getSimpleCredential(kp.getPublic(), kp.getPrivate());
        
        signingParams = new SignatureSigningParameters();
        signingParams.setSigningCredential(signingCred);
        signingParams.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signingParams.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signingParams.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        
        final KeyInfoGeneratorFactory factory =
                DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager().getDefaultManager().getFactory(
                        signingCred);
        assert factory != null;
        signingParams.setKeyInfoGenerator(factory.newInstance());
        
        signatureTrustEngine = new ExplicitKeySignatureTrustEngine(
                new StaticCredentialResolver(signingCred), 
                DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
        
        signatureValidationFilter = new SignatureValidationFilter(signatureTrustEngine);
        signatureValidationFilter.initialize();
    }
    
    @BeforeMethod
    protected void setUpEntityData() throws MarshallingException, IOException, SecurityException, SignatureException {
        
        id1 = "urn:test:entity:1";
        ed1 = buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        ed1.setEntityID(id1);
        ed1.getRoleDescriptors().add((RoleDescriptor) buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME));
        SignatureSupport.signObject(ed1, signingParams);
        Assert.assertTrue(ed1.isSigned());
        
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            XMLObjectSupport.marshallToOutputStream(ed1, baos);
            Assert.assertNotNull(ed1.getDOM());
        }
        
        id2 = "urn:test:entity:2";
        ed2 = buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        ed2.setEntityID(id2);
        ed2.getRoleDescriptors().add((RoleDescriptor) buildXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME));
        SignatureSupport.signObject(ed2, signingParams);
        Assert.assertTrue(ed2.isSigned());
        
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            XMLObjectSupport.marshallToOutputStream(ed2, baos);
            Assert.assertNotNull(ed2.getDOM());
        }
        
        id3 = "urn:test:entity:3";
        ed3 = buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        ed3.setEntityID(id3);
        ed3.getRoleDescriptors().add((RoleDescriptor) buildXMLObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME));
        SignatureSupport.signObject(ed3, signingParams);
        Assert.assertTrue(ed3.isSigned());
        
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            XMLObjectSupport.marshallToOutputStream(ed3, baos);
            Assert.assertNotNull(ed3.getDOM());
        }
    }
    
    @BeforeMethod
    protected void setUp() {
        sourceMap = new HashMap<>();
        persistentCacheMap = new HashMap<>();
        persistentCacheManager = new MapLoadSaveManager<>(persistentCacheMap);
        
        resolver = new MockDynamicResolver(sourceMap);
        resolver.setId("test123");
        resolver.setActivationCondition(prc -> {return allowActivation;});
        resolver.setParserPool(Constraint.isNotNull(XMLObjectProviderRegistrySupport.getParserPool(), "ParserPool missing"));
        
        allowActivation = true;
    }
    
    @AfterMethod
    protected void tearDown() {
        AnnotationsSupport.callOnTeardownAnnotations(resolver);
    }

    
    @Test
    public void testInactive() throws ComponentInitializationException, ResolverException {
        allowActivation = false;
        
        resolver.initialize();
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
    }

    @Test
    public void testNoEntities() throws ComponentInitializationException, ResolverException {
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().isEmpty());
    }
    
    @Test
    public void testBasicResolution() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        sourceMap.put(id2, ed2);
        sourceMap.put(id3, ed3);
        
        resolver.initialize();
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
        
        DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id1));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id1).size(), 1);
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id2));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id2).size(), 1);
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id3));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id3).size(), 1);
    }
    
    @Test
    public void testClear() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        sourceMap.put(id2, ed2);
        sourceMap.put(id3, ed3);
        
        resolver.initialize();
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        resolver.clear();
        
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id2));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id3));
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
    }
    
    @Test
    public void testClearByEntityID() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        sourceMap.put(id2, ed2);
        sourceMap.put(id3, ed3);
        
        resolver.initialize();
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        resolver.clear(id1);
        resolver.clear(id2);
        
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id2));
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id3));
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
    }
    
    @Test
    public void testNegativeLookupCache() throws ComponentInitializationException, ResolverException, InterruptedException {
        resolver.setNegativeLookupCacheDuration(Duration.ofSeconds(2));
        
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        
        sourceMap.put(id1, ed1);
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        
        Thread.sleep(2500);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id1));
    }
    
    @Test
    public void testGlobalClearWithNegativeLookupCache() throws ComponentInitializationException, ResolverException, InterruptedException {
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        
        sourceMap.put(id1, ed1);
        
        resolver.clear();
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id1));
    }
    
    @Test
    public void testEntityIDClearWithNegativeLookupCache() throws ComponentInitializationException, ResolverException, InterruptedException {
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id1));
        
        sourceMap.put(id1, ed1);
        
        resolver.clear(id1);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id1));
    }
    
    @Test
    public void testDOMDropFromFetch() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        
        resolver.initialize();
        
        EntityDescriptor result = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1)));
        
        assert result != null;
        Assert.assertNull(result.getDOM());
    }
    
    public void testBasicResolutionWithPersistentCache() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        sourceMap.put(id2, ed2);
        sourceMap.put(id3, ed3);
        
        resolver.setPersistentCacheManager(persistentCacheManager);
        resolver.initialize();
        
        Assert.assertTrue(resolver.isPersistentCachingEnabled());
        
        Assert.assertEquals(persistentCacheMap.size(), 0);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        
        Assert.assertEquals(persistentCacheMap.size(), 1);
        
        String cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed1);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed1);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed2);
        
        Assert.assertEquals(persistentCacheMap.size(), 3);
        
        cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed2);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed2);
        
        cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed3);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed3);
        
    }
    
    @Test
    public void testWithPersistentCache() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        sourceMap.put(id2, ed2);
        sourceMap.put(id3, ed3);
        
        resolver.setPersistentCacheManager(persistentCacheManager);
        resolver.initialize();
        
        Assert.assertTrue(resolver.isPersistentCachingEnabled());
        
        Assert.assertEquals(persistentCacheMap.size(), 0);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        
        Assert.assertEquals(persistentCacheMap.size(), 1);
        
        String cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed1);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed1);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
        
        Assert.assertEquals(persistentCacheMap.size(), 3);
        
        cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed2);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed2);
        
        cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed3);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed3);
        
    }
    
    @Test
    public void testWithPersistentCacheAndSignatureValidation() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        sourceMap.put(id2, ed2);
        sourceMap.put(id3, ed3);
        
        resolver.setPersistentCacheManager(persistentCacheManager);
        resolver.setMetadataFilter(signatureValidationFilter);
        resolver.initialize();
        
        Assert.assertTrue(resolver.isPersistentCachingEnabled());
        
        Assert.assertEquals(persistentCacheMap.size(), 0);
        
        Assert.assertNotNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
        
        EntityDescriptor ed = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1)));
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), id1);
        
        Assert.assertEquals(persistentCacheMap.size(), 1);
        
        String cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed1);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed1);
        
        ed = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2)));
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), id2);
        
        ed = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3)));
        assert ed != null;
        Assert.assertEquals(ed.getEntityID(), id3);
        
        Assert.assertEquals(persistentCacheMap.size(), 3);
        
        cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed2);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed2);
        
        cacheKey = resolver.getPersistentCacheKeyGenerator().apply(ed3);
        Assert.assertTrue(persistentCacheMap.containsKey(cacheKey));
        Assert.assertSame(persistentCacheMap.get(cacheKey), ed3);
        
    }
    
    @Test
    public void testInitFromPersistentCache() throws ComponentInitializationException, ResolverException, IOException {
        persistentCacheKeyGenerator = new AbstractDynamicMetadataResolver.DefaultCacheKeyGenerator();
        persistentCacheManager.save(persistentCacheKeyGenerator.apply(ed1), ed1);
        persistentCacheManager.save(persistentCacheKeyGenerator.apply(ed2), ed2);
        persistentCacheManager.save(persistentCacheKeyGenerator.apply(ed3), ed3);
        
        resolver.setPersistentCacheManager(persistentCacheManager);
        resolver.setPersistentCacheKeyGenerator(persistentCacheKeyGenerator);
        resolver.setInitializeFromPersistentCacheInBackground(false);
        
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        // These will be there before any resolve() calls, loaded from the persistent cache
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id1));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id1).size(), 1);
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id2));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id2).size(), 1);
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id3));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id3).size(), 1);
        
        Assert.assertTrue(sourceMap.isEmpty());
        
        for (final String entityID : List.of(id1, id2, id3)) {
            EntityDescriptor ed = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityID)));
            assert ed != null;
            Assert.assertEquals(ed.getEntityID(), entityID);
            Assert.assertNull(ed.getDOM());
        }
    }
    
    @Test
    public void testInitFromPersistentCacheWithPredicate() throws ComponentInitializationException, ResolverException, IOException {
        persistentCacheKeyGenerator = new AbstractDynamicMetadataResolver.DefaultCacheKeyGenerator();
        persistentCacheManager.save(persistentCacheKeyGenerator.apply(ed1), ed1);
        persistentCacheManager.save(persistentCacheKeyGenerator.apply(ed2), ed2);
        persistentCacheManager.save(persistentCacheKeyGenerator.apply(ed3), ed3);
        
        resolver.setPersistentCacheManager(persistentCacheManager);
        resolver.setPersistentCacheKeyGenerator(persistentCacheKeyGenerator);
        resolver.setInitializeFromPersistentCacheInBackground(false);
        
        // Only load id1 from the cache
        resolver.setInitializationFromCachePredicate(
                new Predicate<EntityDescriptor>() {
                    public boolean test(EntityDescriptor input) {
                        if (input == null) {
                            return false;
                        }
                        return Objects.equals(id1, input.getEntityID());
                    }
                });
        
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        // This will be there before any resolve() calls, loaded from the persistent cache
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id1));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id1).size(), 1);
        
        // These were filtered out by the predicate
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id2));
        Assert.assertFalse(backingStore.getIndexedDescriptors().containsKey(id3));
        
        
        Assert.assertTrue(sourceMap.isEmpty());
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))));
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))));
    }
    
    @Test
    public void testInitFromPersistentCacheWithDifferingKeys() throws ComponentInitializationException, ResolverException, IOException {
        persistentCacheKeyGenerator = new AbstractDynamicMetadataResolver.DefaultCacheKeyGenerator();
        persistentCacheManager.save("one", ed1);
        persistentCacheManager.save("two", ed2);
        persistentCacheManager.save("three", ed3);
        
        resolver.setPersistentCacheManager(persistentCacheManager);
        resolver.setPersistentCacheKeyGenerator(persistentCacheKeyGenerator);
        resolver.setInitializeFromPersistentCacheInBackground(false);
        
        resolver.initialize();
        
        // Keys should have been updated
        Assert.assertFalse(persistentCacheMap.containsKey("one"));
        Assert.assertTrue(persistentCacheMap.containsKey(persistentCacheKeyGenerator.apply(ed1)));
        
        Assert.assertFalse(persistentCacheMap.containsKey("two"));
        Assert.assertTrue(persistentCacheMap.containsKey(persistentCacheKeyGenerator.apply(ed2)));
        
        Assert.assertFalse(persistentCacheMap.containsKey("three"));
        Assert.assertTrue(persistentCacheMap.containsKey(persistentCacheKeyGenerator.apply(ed3)));
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        
        // These will be there before any resolve() calls, loaded from the persistent cache
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id1));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id1).size(), 1);
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id2));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id2).size(), 1);
        
        Assert.assertTrue(backingStore.getIndexedDescriptors().containsKey(id3));
        Assert.assertEquals(backingStore.getIndexedDescriptors().get(id3).size(), 1);
        
        Assert.assertTrue(sourceMap.isEmpty());
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
    }
    
    @Test
    public void testSecondaryIndexAfterEntityIDResolution() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        
        HashSet<MetadataIndex> indexes = new HashSet<>();
        indexes.add(new FunctionDrivenMetadataIndex(new UppercaseEntityIdDescriptorFunction(), new SimpleStringCriteriaFunction()));
        resolver.setIndexes(indexes);
        
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        Optional<Set<String>> indexedData = Optional.empty();
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new SimpleStringCriterion(id1.toUpperCase()))));
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        
        indexedData = backingStore.getSecondaryIndexManager().lookupIndexedItems(new CriteriaSet(new SimpleStringCriterion(id1.toUpperCase())));
        Assert.assertTrue(indexedData.isPresent());
        Assert.assertEquals(indexedData.get(), Set.of(id1));
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new SimpleStringCriterion(id1.toUpperCase()))), ed1);
    }
        
    @Test
    public void testSecondaryIndexAfterEntityIDResolutionMultipleResults() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1, ed1);
        sourceMap.put(id2, ed2);
        sourceMap.put(id3, ed3);
        
        HashSet<MetadataIndex> indexes = new HashSet<>();
        indexes.add(new RoleMetadataIndex());
        resolver.setIndexes(indexes);
        
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        Optional<Set<String>> indexedData = null;
        
        Set<EntityDescriptor> results = new HashSet<>();
        
        results.clear();
        Iterables.addAll(results, resolver.resolve(new CriteriaSet(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME))));
        Assert.assertEquals(results.size(), 0);
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
        
        indexedData = backingStore.getSecondaryIndexManager().lookupIndexedItems(new CriteriaSet(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME)));
        Assert.assertTrue(indexedData.isPresent());
        Assert.assertEquals(indexedData.get(), Set.of(id1));
        
        results.clear();
        Iterables.addAll(results, resolver.resolve(new CriteriaSet(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME))));
        Assert.assertEquals(results.size(), 1);
        Assert.assertEquals(results, Set.of(ed1));
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id2))), ed2);
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id3))), ed3);
        
        indexedData = backingStore.getSecondaryIndexManager().lookupIndexedItems(new CriteriaSet(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME)));
        Assert.assertTrue(indexedData.isPresent());
        Assert.assertEquals(indexedData.get(), CollectionSupport.setOf(id1, id2));
        
        results.clear();
        Iterables.addAll(results, resolver.resolve(new CriteriaSet(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME))));
        Assert.assertEquals(results.size(), 2);
        Assert.assertEquals(results, CollectionSupport.setOf(ed1, ed2));
    }
    
    @Test
    public void testSecondaryLookupThenEntityID() throws ComponentInitializationException, ResolverException {
        sourceMap.put(id1.toUpperCase(), ed1);
        
        resolver.setSecondaryLookup(true);
        
        HashSet<MetadataIndex> indexes = new HashSet<>();
        indexes.add(new FunctionDrivenMetadataIndex(new UppercaseEntityIdDescriptorFunction(), new SimpleStringCriteriaFunction()));
        resolver.setIndexes(indexes);
        
        resolver.initialize();
        
        final DynamicEntityBackingStore backingStore = resolver.ensureBackingStore();
        Optional<Set<String>> indexedData = null;
        
        Assert.assertNull(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))));
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new SimpleStringCriterion(id1.toUpperCase()))), ed1);
        
        backingStore.getIndexedDescriptors().containsKey(id1);
        
        indexedData = backingStore.getSecondaryIndexManager().lookupIndexedItems(new CriteriaSet(new SimpleStringCriterion(id1.toUpperCase())));
        Assert.assertTrue(indexedData.isPresent());
        Assert.assertEquals(indexedData.get(), Set.of(id1));
        
        Assert.assertSame(resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(id1))), ed1);
    }
    
    // Helper classes
    
    private static class MockDynamicResolver extends AbstractDynamicMetadataResolver {
        
        private Map<String,EntityDescriptor> originSourceMap;
        
        private boolean secondaryLookup;

        public MockDynamicResolver(Map<String, EntityDescriptor> map) {
            this(map, null);
        }
        
        public void setSecondaryLookup(boolean flag) {
            secondaryLookup = flag;
        }
        
        public MockDynamicResolver(Map<String, EntityDescriptor> map, Timer backgroundTaskTimer) {
            super(backgroundTaskTimer);
            originSourceMap = map;
        }

        protected XMLObject fetchFromOriginSource(@Nullable CriteriaSet criteria) throws IOException {
            
            final EntityIdCriterion c1 = criteria != null ? criteria.get(EntityIdCriterion.class) : null;
            if (c1 != null) {
                return originSourceMap.get(c1.getEntityId());
            }
            
            if (secondaryLookup) {
                final SimpleStringCriterion c2 = criteria != null ? criteria.get(SimpleStringCriterion.class) : null; 
                if (c2 != null) {
                    return originSourceMap.get(c2.getValue());
                }
            }
            
            return null;
        }

    }
    
}
