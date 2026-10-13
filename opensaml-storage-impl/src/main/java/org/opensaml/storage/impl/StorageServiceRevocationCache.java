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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.storage.RevocationCache;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.Positive;
import net.shibboleth.shared.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.shared.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * Stores and checks for revocation entries via a {@link StorageService}.
 * 
 * <p>
 * This class is thread-safe and uses a synchronized method to prevent race conditions within the underlying store
 * (lacking an atomic "check and insert" operation).
 * </p>
 * 
 * @since 5.0.0
 */
@ThreadSafeAfterInit
public class StorageServiceRevocationCache extends AbstractIdentifiableInitializableComponent
        implements RevocationCache {

    /** Logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(StorageServiceRevocationCache.class);

    /** Backing storage for the replay cache. */
    @NonnullAfterInit private StorageService storage;

    /** Flag controlling behavior on storage failure. */
    private boolean strict;

    /** Default lifetime of revocation entry. Default value: 6 hours */
    @Nonnull @Positive private Duration expires;

    /**
     * Constructor.
     */
    public StorageServiceRevocationCache() {
        expires = Duration.ofHours(6);
    }

    /**
     * Set the default revocation entry expiration.
     * 
     * @param entryExpiration lifetime of an revocation entry in milliseconds
     */
    public void setEntryExpiration(@Positive @Nonnull final Duration entryExpiration) {
        checkSetterPreconditions();
        
        Constraint.isTrue(entryExpiration != null && !entryExpiration.isNegative() && !entryExpiration.isZero(),
                "Revocation cache default entry expiration must be greater than 0");
        expires = entryExpiration;
    }

    /**
     * Get the backing store for the cache.
     * 
     * @return the backing store.
     */
    @NonnullAfterInit public StorageService getStorage() {
        return storage;
    }

    /**
     * Set the backing store for the cache.
     * 
     * @param storageService backing store to use
     */
    public void setStorage(@Nonnull final StorageService storageService) {
        checkSetterPreconditions();

        storage = Constraint.isNotNull(storageService, "StorageService cannot be null");
        Constraint.isTrue(storage.getCapabilities().isServerSide(), "StorageService cannot be client-side");
    }

    /**
     * Get the strictness flag.
     * 
     * @return true iff we should treat storage failures as a revocation
     */
    public boolean isStrict() {
        return strict;
    }

    /**
     * Set the strictness flag.
     * 
     * @param flag true iff we should treat storage failures as a revocation
     */
    public void setStrict(final boolean flag) {
        checkSetterPreconditions();

        strict = flag;
    }

    /** {@inheritDoc} */
    @Override
    public void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (storage == null) {
            throw new ComponentInitializationException("StorageService cannot be null");
        }
    }
    
    /** {@inheritDoc} */
    public synchronized boolean revoke(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key,
            @Nonnull @NotEmpty final String value) {
        return revoke(context, key, value, expires);
    }
    
    /** {@inheritDoc} */
    public synchronized boolean revoke(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String s,
            @Nonnull @NotEmpty final String value, @Nonnull final Duration exp) {
        checkComponentActive();
        
        final String key;
        final StorageCapabilities caps = storage.getCapabilities();
        if (context.length() > caps.getContextSize()) {
            log.error("context {} too long for StorageService (limit {})", context, caps.getContextSize());
            return false;
        } else if (s.length() > caps.getKeySize()) {
            key = sha1Hex(s);
        } else {
            key = s;
        }
        try {
            final StorageRecord<?> entry = storage.read(context, key);
            if (entry == null) {
                log.debug("Entry '{}' of context '{}' is not yet on list of revoked entries,"
                        + " adding to cache with expiration time {}", key, context, expires);
                storage.create(context, key, value, Instant.now().plus(exp).toEpochMilli());
                return true;
            }
            
            storage.updateExpiration(context, key, Instant.now().plus(exp).toEpochMilli());
            log.debug("Entry '{}' of context '{}' was already revoked, updating expiration", key, context);
            return true;
        } catch (final IOException e) {
            log.error("Exception reading/writing to storage service, returning {}", strict ? "failure" : "success", e);
            return !strict;
        }
    }
    
    /** {@inheritDoc} */
    public synchronized boolean unrevoke(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String s) {
        checkComponentActive();
        
        final String key;
        final StorageCapabilities caps = storage.getCapabilities();
        if (context.length() > caps.getContextSize()) {
            log.error("context {} too long for StorageService (limit {})", context, caps.getContextSize());
            return false;
        } else if (s.length() > caps.getKeySize()) {
            key = sha1Hex(s);
        } else {
            key = s;
        }

        try {
            return storage.delete(context, key);
        } catch (final IOException e) {
            log.error("Exception writing to storage service", e);
            return false;
        }
    }

    /** {@inheritDoc} */
    public synchronized boolean isRevoked(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String s) {
        checkComponentActive();

        final String key;
        final StorageCapabilities caps = storage.getCapabilities();
        if (context.length() > caps.getContextSize()) {
            log.error("context {} too long for StorageService (limit {})", context, caps.getContextSize());
            return true;
        } else if (s.length() > caps.getKeySize()) {
            key = sha1Hex(s);
        } else {
            key = s;
        }

        try {
            final StorageRecord<?> entry = storage.read(context, key);
            if (entry == null) {
                log.debug("Entry '{}' is not revoked", key);
                return false;
            }
            
            log.debug("Entry '{}' is revoked", s);
            return true;
        } catch (final IOException e) {
            log.error("Exception reading  storage service, indicating {}",
                    strict ? "revoked" : "not revoked", e);
            return strict;
        }
    }

    /** {@inheritDoc} */
    @Nullable @NotEmpty public synchronized String getRevocationRecord(@Nonnull @NotEmpty final String context,
            @Nonnull @NotEmpty final String s) throws IOException {
        checkComponentActive();

        final String key;
        final StorageCapabilities caps = storage.getCapabilities();
        if (context.length() > caps.getContextSize()) {
            log.error("context {} too long for StorageService (limit {})", context, caps.getContextSize());
            throw new IOException("Context exceeded storage service limit.");
        } else if (s.length() > caps.getKeySize()) {
            key = sha1Hex(s);
        } else {
            key = s;
        }

        try {
            final StorageRecord<?> entry = storage.read(context, key);
            if (entry == null) {
                log.debug("Entry '{}' is not revoked", key);
                return null;
            }
        
            log.debug("Entry '{}' is revoked", s);
            return entry.getValue();
        } catch (final IOException e) {
            if (strict) {
                throw e;
            }
            
            log.error("Exception reading from storage service, non-strict so treating as non-revoked", e);
            return null;
        }
    }

    /**
     * Compute the hex-encoded SHA-1 digest of the UTF-8 form of a string.
     *
     * @param s the string to digest
     *
     * @return the lowercase hex-encoded digest
     */
    @Nonnull private static String sha1Hex(@Nonnull final String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(
                    s.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            // Can't actually happen, SHA-1 is always supported.
            throw new UnsupportedOperationException(e);
        }
    }
    
}
