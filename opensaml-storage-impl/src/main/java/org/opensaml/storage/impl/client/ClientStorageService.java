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

package org.opensaml.storage.impl.client;

import java.io.IOException;
import java.security.KeyException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.TimerTask;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.storage.AbstractMapBackedStorageService;
import org.opensaml.storage.MutableStorageRecord;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.impl.client.ClientStorageServiceStore.Factory;
import org.opensaml.storage.impl.client.JSONClientStorageServiceStore.JSONClientStorageServiceStoreFactory;
import org.slf4j.Logger;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import net.shibboleth.shared.annotation.constraint.Live;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.ConstraintViolationException;
import net.shibboleth.shared.net.CookieManager;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.NonnullSupplier;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.security.DataExpiredException;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.DataSealerException;
import net.shibboleth.shared.security.DataSealerKeyStrategy;
import net.shibboleth.shared.security.KeyExpiredException;

/**
 * Implementation of {@link org.opensaml.storage.StorageService} that stores data in-memory in a
 * shared session attribute.
 * 
 * <p>The data for this service is managed in a {@link ClientStorageServiceStore} object, which must
 * be created by some operation within the container for this implementation to function. Actual
 * load/store of the data to/from that object is driven via companion classes. The serialization
 * of data is inside the storage object class, but the encryption/decryption is here.</p>
 */
public class ClientStorageService extends AbstractMapBackedStorageService implements Filter, StorageCapabilities {

    /** Name of session attribute for session lock. */
    @Nonnull protected static final String LOCK_ATTRIBUTE =
            "org.opensaml.storage.impl.client.ClientStorageService.lock";

    /** Name of session attribute for storage object. */
    @Nonnull protected static final String STORAGE_ATTRIBUTE = 
            "org.opensaml.storage.impl.client.ClientStorageService.store";
    
    /** Enumeration of possible sources for the data. */
    public enum ClientStorageSource {
        /** Source was a cookie. */
        COOKIE,
        
        /** Source was HTML Local Storage. */
        HTML_LOCAL_STORAGE,
    }

    /** Default label for storage tracking. */
    @Nonnull @NotEmpty private static final String DEFAULT_STORAGE_NAME = "shib_idp_client_ss";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ClientStorageService.class);

    /** Sizes to report for context, key, and value limits when particular sources are used. */
    @Nonnull @NotEmpty private Map<ClientStorageSource,Integer> capabilityMap; 

    /** Servlet request Supplier. */
    @NonnullAfterInit private NonnullSupplier<HttpServletRequest> httpServletRequestSupplier;
    
    /** Manages creation of cookies. */
    @NonnullAfterInit private CookieManager cookieManager;
    
    /** Label used to track storage. */
    @Nonnull @NotEmpty private String storageName;
    
    /** DataSealer instance to secure data. */
    @NonnullAfterInit private DataSealer dataSealer;

    /** KeyStrategy enabling us to detect whether data has been sealed with an older key. */
    @Nullable private DataSealerKeyStrategy keyStrategy;
    
    /** Factory for backing store. */
    @Nonnull private Factory storeFactory;

    /** Constructor. */
    public ClientStorageService() {
        storageName = DEFAULT_STORAGE_NAME;
        capabilityMap = new HashMap<>(2);
        capabilityMap.put(ClientStorageSource.COOKIE, 4096);
        capabilityMap.put(ClientStorageSource.HTML_LOCAL_STORAGE, 1024 * 1024);
        storeFactory = new JSONClientStorageServiceStoreFactory();
    }

    /** {@inheritDoc} */
    @Override
    public synchronized void setCleanupInterval(@Nullable final Duration interval) {
        // Don't allow a cleanup task.
        super.setCleanupInterval(Duration.ZERO);
    }
    
    /**
     * Set the map of storage sources to capability/size limits.
     * 
     * <p>The defaults include 4192 characters for cookies and 1024^2 characters
     * for local storage.</p>
     * 
     * @param map capability map
     */
    public void setCapabilityMap(@Nonnull final Map<ClientStorageSource,Integer> map) {
        checkSetterPreconditions();
        Constraint.isNotNull(map, "Capability map cannot be null");
        
        for (final Map.Entry<ClientStorageSource,Integer> entry : map.entrySet()) {
            if (entry.getKey() != null && entry.getValue() != null) {
                capabilityMap.put(entry.getKey(), entry.getValue());
            }
        }
    }
    
    // Checkstyle: CyclomaticComplexity ON
    
    /** {@inheritDoc} */
    public boolean isServerSide() {
        return false;
    }

    /** {@inheritDoc} */
    public boolean isClustered() {
        return true;
    }

    /**
     * Set the Supplier for the servlet request in which to manage per-request data.
     * 
     * @param requestSupplier supplier for the servlet request in which to manage data
     */
    public void setHttpServletRequestSupplier(@Nonnull final NonnullSupplier<HttpServletRequest> requestSupplier) {
        checkSetterPreconditions();
        httpServletRequestSupplier = Constraint.isNotNull(requestSupplier, "HttpServletRequest cannot be null");
    }

    /**
     * Get the current HTTP request if available.
     *
     * @return current HTTP request
     */
    @Nonnull private HttpServletRequest getHttpServletRequest() {
        return httpServletRequestSupplier.get();
    }
    
    /**
     * Get the {@link CookieManager} to use.
     * 
     * @return the CookieManager to use
     */
    @NonnullAfterInit public CookieManager getCookieManager() {
        return cookieManager;
    }
    
    /**
     * Set the {@link CookieManager} to use.
     * 
     * @param manager the CookieManager to use.
     */
    public void setCookieManager(@Nonnull final CookieManager manager) {
        checkSetterPreconditions();
        cookieManager = Constraint.isNotNull(manager, "CookieManager cannot be null");
    }

    /**
     * Get the label to use for storage tracking.
     * 
     * @return label to use
     */
    @Nonnull @NotEmpty public String getStorageName() {
        return storageName;
    }
    
    /**
     * Set the label to use for storage tracking.
     * 
     * @param name label to use
     */
    public void setStorageName(@Nonnull @NotEmpty final String name) {
        checkSetterPreconditions();
        storageName = Constraint.isNotNull(StringSupport.trimOrNull(name), "Storage name cannot be null or empty");
    }
    
    /**
     * Get the {@link DataSealer} to use for data security.
     * 
     * @return {@link DataSealer} to use for data security
     */
    @NonnullAfterInit public DataSealer getDataSealer() {
        return dataSealer;
    }
    
    /**
     * Set the {@link DataSealer} to use for data security.
     * 
     * @param sealer {@link DataSealer} to use for data security
     */
    public void setDataSealer(@Nonnull final DataSealer sealer) {
        checkSetterPreconditions();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
    }

    /**
     * Set the {@link DataSealerKeyStrategy} to use for stale key detection.
     * 
     * @param strategy {@link DataSealerKeyStrategy} to use for stale key detection
     */
    public void setKeyStrategy(@Nullable final DataSealerKeyStrategy strategy) {
        checkSetterPreconditions();
        
        keyStrategy = strategy;
    }
    
    /**
     * Set the backing store {@link Factory} to use. 
     * 
     * @param factory factory to use
     */
    public void setClientStorageServiceStoreFactory(@Nonnull final Factory factory) {
        checkSetterPreconditions();
        
        storeFactory = Constraint.isNotNull(factory, "Factory cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        
    }

    /** {@inheritDoc} */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException,
            ServletException {
        // This is just a no-op available to preserve compatibility with web.xml references to the
        // older storage plugin that saved modified data back to a cookie on every response.
        chain.doFilter(request, response);
    }
    
    /** {@inheritDoc} */
    @Override
    public int getContextSize() {
        try {
            return capabilityMap.get(getSource());
        } catch (final IOException e) {
            return capabilityMap.get(ClientStorageSource.COOKIE);
        }
    }

    /** {@inheritDoc} */
    @Override
    public int getKeySize() {
        return getContextSize();
    }

    /** {@inheritDoc} */
    @Override
    public long getValueSize() {
        return getContextSize();
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (httpServletRequestSupplier == null) {
            throw new ComponentInitializationException("HttpServletRequestSupplier must be set");
        } else if (dataSealer == null || cookieManager == null) {
            throw new ComponentInitializationException("DataSealer and CookieManager must be set");
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nullable protected TimerTask getCleanupTask() {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected ReadWriteLock getLock() {
        final HttpSession session = Constraint.isNotNull(getHttpServletRequest().getSession(), 
                "HttpSession cannot be null");
        
        // Uses a lock bound to the session, creating one if this is the first attempt.
        
        Object lock = session.getAttribute(LOCK_ATTRIBUTE + '.' + storageName);
        if (lock == null || !(lock instanceof ReadWriteLock)) {
            synchronized (this) {
                // Recheck, somebody might have snuck in.
                lock = session.getAttribute(LOCK_ATTRIBUTE + '.' + storageName);
                if (lock == null) {
                    lock = new ReentrantReadWriteLock();
                    session.setAttribute(LOCK_ATTRIBUTE + '.' + storageName, lock);
                }
            }
        }
        
        return (ReadWriteLock) lock;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull @Live protected Map<String, Map<String, MutableStorageRecord<?>>> getContextMap()
            throws IOException {
        
        try {
            final HttpSession session = Constraint.isNotNull(getHttpServletRequest().getSession(),
                    "HttpSession cannot be null");
            final Object store = Constraint.isNotNull(session.getAttribute(STORAGE_ATTRIBUTE + '.' + storageName),
                    "Storage object was not present in session");
            return ((ClientStorageServiceStore) store).getContextMap();
        } catch (final ConstraintViolationException e) {
            throw new IOException(e);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void setDirty() throws IOException {
        try {
            final HttpSession session = Constraint.isNotNull(getHttpServletRequest().getSession(),
                    "HttpSession cannot be null");

            final Object store = session.getAttribute(STORAGE_ATTRIBUTE + '.' + storageName);
            if (store != null && store instanceof ClientStorageServiceStore) {
                ((ClientStorageServiceStore) store).setDirty(true);
            }
        } catch (final ConstraintViolationException e) {
            throw new IOException(e);
        }
    }
    
    /**
     * Get the backing source of the loaded data.
     * 
     * <p>This method should <strong>not</strong> be called while holding the session lock
     * returned by {@link #getLock()}.</p>
     *  
     * @return the source of the loaded data
     * 
     * @throws IOException to signal an error
     */
    @Nullable ClientStorageSource getSource() throws IOException {
       final Lock lock = getLock().readLock();
       try {
           lock.lock();
           
           final HttpSession session = Constraint.isNotNull(getHttpServletRequest().getSession(),
                   "HttpSession cannot be null");
           final Object object = session.getAttribute(STORAGE_ATTRIBUTE + '.' + storageName);
           if (object != null && object instanceof ClientStorageServiceStore) {
               return ((ClientStorageServiceStore) object).getSource();
           }
           return ClientStorageSource.COOKIE;
       } catch (final ConstraintViolationException e) {
           throw new IOException(e);
       } finally {
           lock.unlock();
       }
    }

    /**
     * Check whether data from the client has been loaded into the current session.
     * 
     * <p>This method should <strong>not</strong> be called while holding the session lock
     * returned by {@link #getLock()}.</p>
     *  
     * @return true iff the {@link HttpSession} contains a storage object
     * 
     * @throws IOException to signal an error
     */
    boolean isLoaded() throws IOException {
       final Lock lock = getLock().readLock();
       try {
           lock.lock();
           
           final HttpSession session = Constraint.isNotNull(getHttpServletRequest().getSession(),
                   "HttpSession cannot be null");
           return session.getAttribute(STORAGE_ATTRIBUTE + '.' + storageName) instanceof ClientStorageServiceStore;
       } catch (final ConstraintViolationException e) {
           throw new IOException(e);
       } finally {
           lock.unlock();
       }
    }
    
    /**
     * Reconstitute stored data and inject it into the session.
     * 
     * <p>This method should <strong>not</strong> be called while holding the session lock
     * returned by {@link #getLock()}.</p>
     * 
     * @param raw encrypted data to load as storage contents, or null if none
     * @param source indicates source of the data for later use
     */
    void load(@Nullable @NotEmpty final String raw, @Nonnull final ClientStorageSource source) {

        ClientStorageServiceStore storageObject;
        
        if (raw != null) {
            log.trace("{} Loading storage state into session", getLogPrefix());
            try {
                final StringBuffer keyAliasUsed = new StringBuffer();
                final String decrypted = dataSealer.unwrap(raw, keyAliasUsed);
                
                log.trace("{} Data after decryption: {}", getLogPrefix(), decrypted);
                
                storageObject = storeFactory.load(decrypted, source);
                
                if (keyStrategy != null) {
                    try {
                        if (!keyStrategy.getDefaultKeyRecord().name().equals(keyAliasUsed.toString())) {
                            storageObject.setDirty(true);
                        }
                    } catch (final KeyException e) {
                        log.error("{} Exception while accessing default key during stale key detection",
                                getLogPrefix(), e);
                    }
                }
                
                log.debug("{} Successfully decrypted and loaded storage state from client", getLogPrefix());
            } catch (final KeyExpiredException e) {
                log.debug("{} Secret key used to secure data expired or missing", getLogPrefix());
                storageObject = storeFactory.load(null, source);
                storageObject.setDirty(true);
            } catch (final DataExpiredException e) {
                log.debug("{} Secured data has expired", getLogPrefix());
                storageObject = storeFactory.load(null, source);
                storageObject.setDirty(true);
            } catch (final DataSealerException e) {
                log.error("{} Exception unwrapping secured data", getLogPrefix(), e);
                storageObject = storeFactory.load(null, source);
                storageObject.setDirty(true);
            }
        } else {
            log.trace("{} Initializing empty storage state into session", getLogPrefix());
            storageObject = storeFactory.load(null, source);
        }
        
        // The object should be loaded, and marked "clean", or in the event of just about any failure
        // it should be empty and marked "dirty" to force an overwrite of the expired or corrupted data.
        
        final Lock lock = getLock().writeLock();
        try {
            lock.lock();
            
            final HttpSession session = Constraint.isNotNull(getHttpServletRequest().getSession(),
                    "HttpSession cannot be null");
            session.setAttribute(STORAGE_ATTRIBUTE + '.' + storageName, storageObject);
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * Serialize the stored data if it's in a "modified/dirty" state.
     * 
     * <p>This method should <strong>not</strong> be called while holding the session lock
     * returned by {@link #getLock()}.</p>
     * 
     * @return if dirty, the operation to perform, if not dirty, a null value  
     */
    @Nullable ClientStorageServiceOperation save() {
        
        log.trace("{} Preserving storage state from session", getLogPrefix());
        
        final Lock lock = getLock().writeLock();
        try {
            lock.lock();
            
            final HttpSession session = Constraint.isNotNull(getHttpServletRequest().getSession(),
                    "HttpSession cannot be null");
            
            final Object object = session.getAttribute(STORAGE_ATTRIBUTE + '.' + storageName);
            if (object == null || !(object instanceof ClientStorageServiceStore)) {
                log.error("{} No storage object found in session", getLogPrefix());
                return null;
            }

            try {
                return ((ClientStorageServiceStore) object).save(this);
            } catch (final IOException e) {
                log.error("{} Error while serializing storage data", getLogPrefix(), e);
                return null;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Get a prefix for log messages.
     * 
     * @return  logging prefix
     */
    @Nonnull @NotEmpty String getLogPrefix() {
        return "StorageService " + getId() + ":";
    }
        
}
