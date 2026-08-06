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

package org.opensaml.storage.impl.memcached;

import net.shibboleth.shared.annotation.OnTeardown;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.Positive;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import net.spy.memcached.CASResponse;
import net.spy.memcached.CASValue;
import net.spy.memcached.MemcachedClient;
import net.spy.memcached.internal.OperationFuture;
import net.spy.memcached.transcoders.Transcoder;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.cryptacular.util.HashUtil;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageSerializer;
import org.opensaml.storage.StorageService;
import org.opensaml.storage.VersionMismatchException;
import org.opensaml.storage.annotation.AnnotationSupport;
import org.slf4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Memcached storage service. The implementation of context names is based on the implementation of
 * <em>simulated namespaces</em> discussed on the Memcached project site:
 * <p>
 * <a href="https://code.google.com/p/memcached/wiki/NewProgrammingTricks#Namespacing">
 *     https://code.google.com/p/memcached/wiki/NewProgrammingTricks#Namespacing</a>
 * <p>
 * This storage service supports arbitrary-length context names and keys despite the 250-byte limit on memcached keys.
 * Keys whose length is greater than 250 bytes are hashed using the SHA-512 algorithm and hex encoded to produce a
 * 128-character key that is stored in memcached. Collisions are avoided irrespective of hashing by using the memcached
 * add operation on all create operations which guarantees that an entry is created if and only if a key of the
 * same value does not already exist. Note that context names and keys are assumed to have single-byte encodings in
 * UTF-8 (i.e. ASCII characters) such that key lengths are equal to their size in bytes. Hashed keys naturally meet
 * this requirement.
 * <p>
 * An optional context key-tracking feature is available to support {@link #updateContextExpiration(String, Long)}.
 * Key tracking is disabled by default, but can be enabled by setting the <code>enableContextKeyTracking</code>
 * parameter in the {@link #MemcachedStorageService(net.spy.memcached.MemcachedClient, int, boolean)} constructor.
 * While there is modest performance impact for create and delete operations, the feature limits the number of keys
 * per context. With the default 1M memcached slab size, in the worst case 4180 keys are permitted per context.
 * In many if not most situations the value is easily double that. The limitation can be overcome by increasing the
 * slab size, which decreases overall cache memory consumption efficiency. When key tracking is disabled, there is no
 * limit on the number of keys per context other than overall cache capacity.
 * <p>
 * <strong>Limitations and requirements</strong>
 * <ol>
 *     <li>The memcached binary protocol is strong recommended for efficiency and full versioning support.
 *     In particular, {@link #deleteWithVersion(long, String, String)} and {@link #deleteWithVersion(long, Object)}
 *     will throw runtime errors under the ASCII protocol.</li>
 *     <li>Memcached server 1.4.14 or later MUST be used with binary protocol for proper handling of cache entry
 *     expiration values. See the <a href="https://code.google.com/p/memcached/wiki/ReleaseNotes1414">
 *     1.4.14 release notes</a> for details.</li>
 * </ol>
 *
 * @author Marvin S. Addison
 */
public class MemcachedStorageService extends AbstractIdentifiableInitializableComponent implements StorageService {

    /** Key suffix for entry that contains a list of context keys. */
    @Nonnull @NotEmpty protected static final String CTX_KEY_LIST_SUFFIX = ":contextKeyList";

    /** Key suffix for entry that contains a list of deleted context keys. */
    @Nonnull @NotEmpty protected static final String CTX_KEY_DELETED_SUFFIX = ":contextKeyDeletedList";

    /** Delimiter of items in the context key list. */
    @Nonnull @NotEmpty private static final String CTX_KEY_LIST_DELIMITER = "\n";

    /** Maximum length in bytes of memcached keys. */
    private static final int MAX_KEY_LENGTH = 250;

    /** Logger instance. */
    @Nonnull private final Logger logger = LoggerFactory.getLogger(MemcachedStorageService.class);

    /** Handles conversion of {@link MemcachedStorageRecord} to bytes and vice versa. */
    @Nonnull private final Transcoder<MemcachedStorageRecord<?>> storageRecordTranscoder;

    /** Handles conversion of strings to bytes and vice versa. */
    @Nonnull private final Transcoder<String> stringTranscoder;

    /** Invariant storage capabilities. */
    @Nonnull private MemcachedStorageCapabilities storageCapabilities;

    /** Memcached client instance. */
    @Nonnull private final MemcachedClient memcacheClient;

    /** Memcached asynchronous operation timeout in seconds. */
    @Positive private int operationTimeout;

    /** Flag that controls context key tracking. */
    private boolean trackContextKeys;

    /**
     * Creates a new instance.
     *
     * @param client Memcached client object. The client MUST be configured to use the binary memcached protocol,
     *               i.e. {@link net.spy.memcached.BinaryConnectionFactory}, in order for
     *               {@link #deleteWithVersion(long, String, String)} and {@link #deleteWithVersion(long, Object)}
     *               to work correctly. The binary protocol is recommended for efficiency as well.
     * @param timeout Memcached operation timeout in seconds.
     */
    public MemcachedStorageService(@Nonnull final MemcachedClient client, @Positive final int timeout) {
        this(client, timeout, false);
    }


    /**
     * Creates a new instance with optional context key tracking.
     *
     * @param client Memcached client object. The client MUST be configured to use the binary memcached protocol,
     *               i.e. {@link net.spy.memcached.BinaryConnectionFactory}, in order for
     *               {@link #deleteWithVersion(long, String, String)} and {@link #deleteWithVersion(long, Object)}
     *               to work correctly. The binary protocol is recommended for efficiency as well.
     * @param timeout Memcached operation timeout in seconds.
     * @param enableContextKeyTracking True to enable context key tracking, false otherwise. <strong>NOTE</strong>
     *                                 this flag must be set to <code>true</code> in order for
     *                                 {@link #updateContextExpiration(String, Long)} to work. If that capability is
     *                                 not needed, the flag should be set to <code>false</code> for better
     *                                 performance. The feature is disabled by default.
     */
    public MemcachedStorageService(@Nonnull final MemcachedClient client, @Positive final int timeout,
            final boolean enableContextKeyTracking) {
        Constraint.isNotNull(client, "Client cannot be null");
        Constraint.isGreaterThan(0, timeout, "Operation timeout must be positive");
        memcacheClient = client;
        operationTimeout = timeout;
        trackContextKeys = enableContextKeyTracking;
        storageCapabilities = new MemcachedStorageCapabilities();
        storageRecordTranscoder = new StorageRecordTranscoder();
        stringTranscoder = new StringTranscoder();
    }

    /** {@inheritDoc} */
    @Nonnull public StorageCapabilities getCapabilities() {
        return storageCapabilities;
    }

    /**
     * Sets the storage capabilities. This method should be used when the default 1M slab size is changed;
     * the {@link MemcachedStorageCapabilities#getValueSize()} should be set equal to the chosen slab size.
     *
     * @param capabilities Memcached storage capabilities.
     */
    public void setCapabilities(@Nonnull final MemcachedStorageCapabilities capabilities) {
        Constraint.isNotNull(capabilities, "Storage capabilities cannot be null");
        storageCapabilities = capabilities;
    }

    /** {@inheritDoc} */
    public boolean create(@Nonnull @NotEmpty final String context,
                          @Nonnull @NotEmpty final String key,
                          @Nonnull @NotEmpty final String value,
                          @Nullable @Positive final Long expiration) throws IOException {
        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(key), "Key cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(value), "Value cannot be null or empty");
        final MemcachedStorageRecord<?> record = new MemcachedStorageRecord<>(value, expiration);
        final int expiry = record.getExpiry();
        Constraint.isGreaterThan(-1, expiry, "Expiration must be null or positive");
        String namespace = lookupNamespace(context);
        if (namespace == null) {
            namespace = createNamespace(context);
        }
        final String cacheKey = memcachedKey(namespace, key);
        logger.debug("Creating new entry at {} for context={}, key={}, exp={}", cacheKey, context, key, expiry);
        final boolean success =
                handleAsyncResult(memcacheClient.add(cacheKey, expiry, record, storageRecordTranscoder));
        if (success && trackContextKeys) {
            logger.debug("Tracking key {} for context {}", cacheKey, context);
            final boolean result = updateContextKeyList(CTX_KEY_LIST_SUFFIX, namespace, cacheKey);
            if (!result) {
                logger.debug("Failed appending {} to list of keys for context {}", cacheKey, context);
                // Try to clean up record we just created
                // Cache entry expiration will clean it up regardless
                handleAsyncResult(memcacheClient.delete(cacheKey));
            }
            return result;
        }
        return success;
    }

    /** {@inheritDoc} */
    public <T> boolean create(@Nonnull @NotEmpty final String context,
                          @Nonnull @NotEmpty final String key,
                          @Nonnull final T value,
                          @Nonnull final StorageSerializer<T> serializer,
                          @Nullable @Positive final Long expiration) throws IOException {
        Constraint.isNotNull(serializer, "Serializer cannot be null");
        return create(context, key, serializer.serialize(value), expiration);
    }

    /** {@inheritDoc} */
    public boolean create(@Nonnull final Object value) throws IOException {
        Constraint.isNotNull(value, "Value cannot be null");

        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        final String val = AnnotationSupport.getValue(value);
        if (context == null || key == null || val == null) {
            throw new IOException("Context, key, and value must be non-null");
        }

        return create(context, key, val, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    public <T> StorageRecord<T> read(@Nonnull @NotEmpty final String context,
                              @Nonnull @NotEmpty final String key) throws IOException {
        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(key), "Key cannot be null or empty");
        final String namespace = lookupNamespace(context);
        if (namespace == null) {
            logger.debug("Namespace for context {} does not exist", context);
            return null;
        }
        final String cacheKey = memcachedKey(namespace, key);
        logger.debug("Reading entry at {} for context={}, key={}", cacheKey, context, key);
        final CASValue<MemcachedStorageRecord<?>> record;
        try {
            record = this.handleAsyncResult(memcacheClient.asyncGets(cacheKey, storageRecordTranscoder));
        } catch (final RuntimeException e) {
            throw new IOException("Memcached operation failed", e);
        }
        if (record == null) {
            return null;
        }
        record.getValue().setVersion(record.getCas());
        return (StorageRecord<T>) record.getValue();
    }

    /** {@inheritDoc} */
    public Object read(@Nonnull final Object value) throws IOException {
        Constraint.isNotNull(value, "Value cannot be null");

        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }
        return read(context, key);
    }

    /** {@inheritDoc} */
    @Nonnull public <T> Pair<Long, StorageRecord<T>> read(@Nonnull @NotEmpty final String context,
                                           @Nonnull @NotEmpty final String key,
                                           @Positive final long version) throws IOException {
        Constraint.isGreaterThan(0, version, "Version must be positive");
        final StorageRecord<T> record = read(context, key);
        if (record == null) {
            return new Pair<>();
        }
        final Pair<Long, StorageRecord<T>> result = new Pair<>(record.getVersion(), null);
        if (version != record.getVersion()) {
            // Only set the record if it's not the same as the version requested
            result.setSecond(record);
        }
        return result;
    }

    /** {@inheritDoc} */
    public boolean update(@Nonnull @NotEmpty final String context,
                          @Nonnull @NotEmpty final String key,
                          @Nonnull @NotEmpty final String value,
                          @Nullable @Positive final Long expiration) throws IOException {
        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(key), "Key cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(value), "Value cannot be null or empty");
        final MemcachedStorageRecord<?> record = new MemcachedStorageRecord<>(value, expiration);
        final int expiry = record.getExpiry();
        Constraint.isGreaterThan(-1, expiry, "Expiration must be null or positive");
        final String namespace = lookupNamespace(context);
        if (namespace == null) {
            logger.debug("Namespace for context {} does not exist", context);
            return false;
        }
        final String cacheKey = memcachedKey(namespace, key);
        logger.debug("Updating entry at {} for context={}, key={}, exp={}", cacheKey, context, key, expiry);
        return handleAsyncResult(memcacheClient.replace(cacheKey, expiry, record, storageRecordTranscoder));
    }

    /** {@inheritDoc} */
    public <T> boolean update(@Nonnull @NotEmpty final String context,
                          @Nonnull @NotEmpty final String key,
                          @Nonnull final T value,
                          @Nonnull final StorageSerializer<T> serializer,
                          @Nullable @Positive final Long expiration) throws IOException {
        Constraint.isNotNull(serializer, "Serializer cannot be null");
        return update(context, key, serializer.serialize(value), expiration);
    }

    /** {@inheritDoc} */
    public boolean update(@Nonnull final Object value) throws IOException {
        Constraint.isNotNull(value, "Value cannot be null");

        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        final String val = AnnotationSupport.getValue(value);
        if (context == null || key == null || val == null) {
            throw new IOException("Context, key, and value must be non-null");
        }

        return update(context, key, val, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    public Long updateWithVersion(@Positive final long version,
                                  @Nonnull @NotEmpty final String context,
                                  @Nonnull @NotEmpty final String key,
                                  @Nonnull @NotEmpty final String value,
                                  @Nullable @Positive final Long expiration)
            throws IOException, VersionMismatchException {

        Constraint.isGreaterThan(0, version, "Version must be positive");
        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(key), "Key cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(value), "Value cannot be null or empty");
        final MemcachedStorageRecord<?> record = new MemcachedStorageRecord<>(value, expiration);
        final int expiry = record.getExpiry();
        Constraint.isGreaterThan(-1, expiry, "Expiration must be null or positive");
        final String namespace = lookupNamespace(context);
        if (namespace == null) {
            logger.debug("Namespace for context {} does not exist", context);
            return null;
        }
        final String cacheKey = memcachedKey(namespace, key);
        logger.debug("Updating entry at {} for context={}, key={}, version={}, exp={}",
                cacheKey, context, key, version, expiry);
        final CASResponse response = handleAsyncResult(
                memcacheClient.asyncCAS(cacheKey, version, expiry, record, storageRecordTranscoder));
        Long newVersion = null;
        if (CASResponse.OK == response) {
            final CASValue<MemcachedStorageRecord<?>> newRecord = handleAsyncResult(
                    memcacheClient.asyncGets(cacheKey, storageRecordTranscoder));
            if (newRecord != null) {
                newVersion = newRecord.getCas();
            }
        } else if (CASResponse.EXISTS == response) {
            throw new VersionMismatchException();
        }
        return newVersion;
    }

// Checkstyle: ParameterNumber OFF
    /** {@inheritDoc} */
    @Nullable public <T> Long updateWithVersion(@Positive final long version,
                                  @Nonnull @NotEmpty final String context,
                                  @Nonnull @NotEmpty final String key,
                                  @Nonnull final T value,
                                  @Nonnull final StorageSerializer<T> serializer,
                                  @Nullable @Positive final Long expiration)
            throws IOException, VersionMismatchException {

        Constraint.isNotNull(serializer, "Serializer cannot be null");
        return updateWithVersion(version, context, key, serializer.serialize(value), expiration);
    }
// Checkstyle: ParameterNumber ON

    /** {@inheritDoc} */
    @Nullable public Long updateWithVersion(@Positive final long version, @Nonnull final Object value)
            throws IOException, VersionMismatchException {
        Constraint.isNotNull(value, "Value cannot be null");

        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        final String val = AnnotationSupport.getValue(value);
        if (context == null || key == null || val == null) {
            throw new IOException("Context, key, and value must be non-null");
        }

        return updateWithVersion(version, context, key, val, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    public boolean updateExpiration(@Nonnull @NotEmpty final String context,
                                    @Nonnull @NotEmpty final String key,
                                    @Nullable @Positive final Long expiration) throws IOException {
        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(key), "Key cannot be null or empty");
        final int expiry = MemcachedStorageRecord.expiry(expiration);
        Constraint.isGreaterThan(-1, expiry, "Expiration must be null or positive");
        final String namespace = lookupNamespace(context);
        if (namespace == null) {
            logger.debug("Namespace for context {} does not exist", context);
            return false;
        }
        final String cacheKey = memcachedKey(namespace, key);
        logger.debug("Updating expiration for entry at {} for context={}, key={}", cacheKey, context, key);
        return handleAsyncResult(memcacheClient.touch(cacheKey, expiry));
    }

    /** {@inheritDoc} */
    public boolean updateExpiration(@Nonnull final Object value) throws IOException {
        Constraint.isNotNull(value, "Value cannot be null");

        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }

        return updateExpiration(context, key, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    public boolean delete(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key)
            throws IOException {

        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(key), "Key cannot be null or empty");
        final String namespace = lookupNamespace(context);
        if (namespace == null) {
            logger.debug("Namespace for context {} does not exist", context);
            return false;
        }
        final String cacheKey = memcachedKey(namespace, key);
        logger.debug("Deleting entry at {} for context={}, key={}", cacheKey, context, key);
        final boolean success = handleAsyncResult(memcacheClient.delete(cacheKey));
        if (success && trackContextKeys) {
            logger.debug("Noting deletion of key {} for context {}", cacheKey, context);
            if (!updateContextKeyList(CTX_KEY_DELETED_SUFFIX, namespace, cacheKey)) {
                logger.debug("Failed appending {} to list of deleted keys for context {}", cacheKey, context);
            }
        }
        return success;
    }

    /** {@inheritDoc} */
    public boolean delete(@Nonnull final Object value) throws IOException {
        Constraint.isNotNull(value, "Value cannot be null");

        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }

        return delete(context, key);
    }

    /** {@inheritDoc} */
    public boolean deleteWithVersion(@Positive final long version,
                                     @Nonnull @NotEmpty final String context,
                                     @Nonnull @NotEmpty final String key) throws IOException, VersionMismatchException {
        Constraint.isGreaterThan(0, version, "Version must be positive");
        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        Constraint.isNotNull(StringSupport.trimOrNull(key), "Key cannot be null or empty");
        final String namespace = lookupNamespace(context);
        if (namespace == null) {
            logger.debug("Namespace for context {} does not exist", context);
            return false;
        }
        final String cacheKey = memcachedKey(namespace, key);
        logger.debug("Deleting entry at {} for context={}, key={}, version={}", cacheKey, context, key, version);
        final boolean success = handleAsyncResult(memcacheClient.delete(cacheKey, version));
        if (success && trackContextKeys) {
            logger.debug("Noting deletion of key {} for context {}", cacheKey, context);
            if (!updateContextKeyList(CTX_KEY_DELETED_SUFFIX, namespace, cacheKey)) {
                logger.debug("Failed appending {} to list of deleted keys for context {}", cacheKey, context);
            }
        }
        return success;
    }

    /** {@inheritDoc} */
    public boolean deleteWithVersion(@Positive final long version, @Nonnull final Object value)
            throws IOException, VersionMismatchException {
        Constraint.isNotNull(value, "Value cannot be null");

        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }

        return deleteWithVersion(version, context, key);
    }

    /** {@inheritDoc} */
    public void reap(@Nonnull @NotEmpty final String context) throws IOException {
        return;
    }

// Checkstyle: ReturnCount OFF
    /** {@inheritDoc} */
    public void updateContextExpiration(@Nonnull @NotEmpty final String context, @Nullable final Long expiration)
            throws IOException {
        if (!trackContextKeys) {
            throw new UnsupportedOperationException(
                    "updateContextExpiration not supported when trackContextKeys == false");
        }
        final int expiry = MemcachedStorageRecord.expiry(expiration);
        Constraint.isGreaterThan(-1, expiry, "Expiration must be null or positive");
        final String namespace = lookupNamespace(context);
        if (namespace ==  null) {
            logger.debug("Cannot update context expiration since context namespace does not exist");
            return;
        }
        final CASValue<String> keys = handleAsyncResult(
                memcacheClient.asyncGets(namespace + CTX_KEY_LIST_SUFFIX, stringTranscoder));
        if (keys == null) {
            logger.debug("No context keys found to update expiration");
            return;
        }
        final Set<String> keySet = new HashSet<>(Arrays.asList(keys.getValue().split(CTX_KEY_LIST_DELIMITER)));
        final CASValue<String> deletedKeys = handleAsyncResult(
                memcacheClient.asyncGets(namespace + CTX_KEY_DELETED_SUFFIX, stringTranscoder));
        if (deletedKeys != null) {
            keySet.removeAll(Arrays.asList(deletedKeys.getValue().split(CTX_KEY_LIST_DELIMITER)));
        }
        final List<OperationFuture<Boolean>> results = new ArrayList<>(keySet.size());
        for (final String key : keySet) {
            logger.debug("Updating expiration of key {} to {}", key, expiry);
            results.add(memcacheClient.touch(key, expiry));
        }
        for (final OperationFuture<Boolean> result : results) {
            handleAsyncResult(result);
        }
    }
// Checkstyle: ReturnCount ON

    /** {@inheritDoc} */
    public void deleteContext(@Nonnull @NotEmpty final String context) throws IOException {
        Constraint.isNotNull(StringSupport.trimOrNull(context), "Context cannot be null or empty");
        final String namespace = lookupNamespace(context);
        if (namespace == null) {
            logger.debug("Namespace for context {} does not exist. Context values effectively deleted.", context);
            return;
        }
        final OperationFuture<Boolean> ctxResult = memcacheClient.delete(context);
        final OperationFuture<Boolean> nsResult = memcacheClient.delete(namespace);
        if (trackContextKeys) {
            final OperationFuture<Boolean> keyListResult = memcacheClient.delete(namespace + CTX_KEY_LIST_SUFFIX);
            final OperationFuture<Boolean> deletedKeyResult =
                    memcacheClient.delete(namespace + CTX_KEY_DELETED_SUFFIX);
            handleAsyncResult(keyListResult);
            handleAsyncResult(deletedKeyResult);
        }
        handleAsyncResult(ctxResult);
        handleAsyncResult(nsResult);
    }

    /** Teardown entry point. */
    @OnTeardown
    public final void teardownMemcachedStorageService() {
        memcacheClient.shutdown();
    }


    /**
     * Looks up the namespace for the given context name in the cache.
     *
     * @param context Context name.
     *
     * @return Corresponding namespace for given context or null if no namespace exists for context.
     *
     * @throws java.io.IOException On memcached operation errors.
     */
    @Nullable protected String lookupNamespace(@Nonnull @NotEmpty final String context) throws IOException {
        try {
            final CASValue<String> result = handleAsyncResult(
                    memcacheClient.asyncGets(memcachedKey(context), stringTranscoder));
            return result == null ? null : result.getValue();
        } catch (final RuntimeException e) {
            throw new IOException("Memcached operation failed", e);
        }
    }

    /**
     * Creates a cache-wide unique namespace for the given context name. The context-namespace mapping is stored
     * in the cache.
     *
     * @param context Context name.
     *
     * @return Namespace name for given context.
     *
     * @throws java.io.IOException On memcached operation errors.
     */
    @Nonnull protected String createNamespace(@Nonnull @NotEmpty final String context) throws IOException {
        String namespace =  null;
        boolean success = false;
        // Perform successive add operations until success to ensure unique namespace
        while (!success) {
            namespace = CodecUtil.hex(ByteUtil.toBytes(System.currentTimeMillis()));
            // Namespace values are safe for memcached keys
            success = handleAsyncResult(memcacheClient.add(namespace, 0, context, stringTranscoder));
        }
        // Create the reverse mapping to support looking up namespace by context name
        if (!handleAsyncResult(memcacheClient.add(memcachedKey(context), 0, namespace, stringTranscoder))) {
            throw new IllegalStateException(context + " already exists");
        }
        assert namespace != null;
        return namespace;
    }

    /**
     * Creates a memcached key from one or more parts.
     *
     * @param parts Key parts (i.e. namespace, local name)
     *
     * @return Key comprised of 250 characters or less.
     */
    private String memcachedKey(@Nonnull final String ... parts) {
        final String key;
        if (parts.length > 0) {
            final StringBuilder sb = new StringBuilder();
            int i = 0;
            for (final String part : parts) {
                if (i++ > 0) {
                    sb.append(':');
                }
                sb.append(part);
            }
            key = sb.toString();
        } else {
            key = parts[0];
        }
        if (key.length() > MAX_KEY_LENGTH) {
            // TODO: convert to our StringDigester
            return CodecUtil.hex(HashUtil.sha512(key));
        }
        return key;
    }

    /**
     * Handle async result.
     * 
     * @param result the result 
     * @param <T> type of result
     * @return the result
     * @throws IOException if an error occurs
     */
    private <T> T handleAsyncResult(@Nonnull final OperationFuture<T> result) throws IOException {
        try {
            return result.get(operationTimeout, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new IOException("Memcached operation interrupted");
        } catch (final TimeoutException e) {
            throw new IOException("Memcached operation did not complete in time (" + operationTimeout + "s)");
        } catch (final ExecutionException e) {
            throw new IOException("Memcached operation error", e);
        }
    }

    /**
     * Update context key list.
     * 
     * @param suffix the suffix
     * @param namespace the namespace
     * @param key the storage key
     * @return whether the update was a success
     * @throws IOException if an error occurs
     */
    private boolean updateContextKeyList(@Nonnull final String suffix, @Nonnull final String namespace,
            @Nonnull final String key) throws IOException {
        final String listKey = namespace + suffix;
        final String newItem = key + CTX_KEY_LIST_DELIMITER;
        final boolean success = handleAsyncResult(memcacheClient.append(listKey, newItem, stringTranscoder));
        if (!success) {
            // Assume list does not exist and create it
            return handleAsyncResult(memcacheClient.add(listKey, 0, newItem, stringTranscoder));
        }
        return success;
    }
}