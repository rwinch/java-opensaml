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

package org.opensaml.storage.impl;

import static org.testng.Assert.*;

import java.io.IOException;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.Random;

import org.opensaml.storage.impl.client.ClientStorageService;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.ConstraintViolationException;
import net.shibboleth.shared.primitive.AnnotationsSupport;

import org.testng.annotations.BeforeMethod;

/**
 * Tests for {@link StorageServiceRevocationCache}.
 */
@SuppressWarnings("javadoc")
public class StorageServiceRevocationCacheTest {
    
    private MemoryStorageService storageService;
    
    private StorageServiceRevocationCache revocationCache;

    @BeforeMethod
    protected void setUp() throws ComponentInitializationException {
    
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.setCleanupInterval(Duration.ZERO);
        storageService.initialize();
        
        revocationCache = new StorageServiceRevocationCache();
        revocationCache.setId("test");
        revocationCache.setEntryExpiration(Duration.ofMillis(500));
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
    }
    
    @AfterMethod
    protected void tearDown() {
        AnnotationsSupport.callOnTeardownAnnotations(storageService);
    }
    
    @Test
    public void testInit() {
        revocationCache = new StorageServiceRevocationCache();
        try {
            revocationCache.setStorage(new ClientStorageService());
            
            fail("ClientStorageService should have caused constraint violation");
        } catch (final Exception e) {
        }
    }
    
    
    @Test
    public void testStrictSetter() throws ComponentInitializationException {
        assertFalse(revocationCache.isStrict());
        revocationCache = new StorageServiceRevocationCache();
        revocationCache.setId("test");
        revocationCache.setStorage(storageService);
        revocationCache.setStrict(true);
        revocationCache.initialize();
        assertTrue(revocationCache.isStrict());
    }
    
    @Test (expectedExceptions = ConstraintViolationException.class)
    public void testExpirationSetter() {
        //Must be positive
        revocationCache = new StorageServiceRevocationCache();
        revocationCache.setEntryExpiration(Duration.ZERO);
    }
    
    @Test 
    public void testStorageGetter() {
        assertEquals(storageService, revocationCache.getStorage());
    }
    
    @Test 
    public void testRevocationSuccess() {
        assertFalse(revocationCache.isRevoked("context", "item"));
        assertTrue(revocationCache.revoke("context", "item"));
        assertTrue(revocationCache.isRevoked("context", "item"));
    }
    
    @Test 
    public void testRevocationSuccessLongContext() throws ComponentInitializationException {
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.setContextSize(50);
        storageService.setCleanupInterval(Duration.ZERO);
        storageService.initialize();
        
        revocationCache = new StorageServiceRevocationCache();
        revocationCache.setId("test");
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
        
        final byte[] array = new byte[storageService.getCapabilities().getContextSize()*2];
        new Random().nextBytes(array);
        final String context = new String(array, Charset.forName("UTF-8"));
        assertTrue(context.length()>storageService.getCapabilities().getContextSize());
        assertTrue(revocationCache.isRevoked(context, "item"));
        assertFalse(revocationCache.revoke(context, "item"));
    }
    
    @Test 
    public void testRevocationSuccessLongLongItem() throws ComponentInitializationException {
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.setCleanupInterval(Duration.ZERO);
        storageService.setKeySize(50);
        storageService.initialize();
        revocationCache = new StorageServiceRevocationCache();
        revocationCache.setId("test");
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
        final byte[] array = new byte[storageService.getCapabilities().getKeySize()*2];
        new Random().nextBytes(array);
        final String item = new String(array, Charset.forName("UTF-8"));
        assertTrue(item.length()>storageService.getCapabilities().getKeySize());
        assertFalse(revocationCache.isRevoked("context", item));
        assertTrue(revocationCache.revoke("context", item));
        assertTrue(revocationCache.isRevoked("context", item));
    }
    
    @Test 
    public void testRevocationExpirationSuccess() throws InterruptedException {
        //Test expiration of entry (500ms)
        assertFalse(revocationCache.isRevoked("context", "item"));
        assertTrue(revocationCache.revoke("context", "item"));
        Thread.sleep(600L);
        assertFalse(revocationCache.isRevoked("context", "item"));
        //Test rolling window, second revoke updates expiration past original 500ms
        assertTrue(revocationCache.revoke("context", "item"));
        Thread.sleep(300L);
        assertTrue(revocationCache.revoke("context", "item"));
        Thread.sleep(300L);
        assertTrue(revocationCache.isRevoked("context", "item"));
    }

    @Test
    public void testRevokedRecordFetch() throws IOException {
        assertTrue(revocationCache.revoke("context", "item", "value", Duration.ofHours(1)));
        assertNull(revocationCache.getRevocationRecord("context", "item2"));
        assertEquals(revocationCache.getRevocationRecord("context", "item"), "value");
        
    }

    @Test
    public void testRevokedRecordDelete() throws IOException {
        assertTrue(revocationCache.revoke("context", "item", "value", Duration.ofHours(1)));
        assertEquals(revocationCache.getRevocationRecord("context", "item"), "value");
        assertTrue(revocationCache.unrevoke("context", "item"));
        assertNull(revocationCache.getRevocationRecord("context", "item"));
    }

}