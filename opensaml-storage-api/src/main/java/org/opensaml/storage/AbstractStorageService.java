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

package org.opensaml.storage;

import java.io.IOException;
import java.time.Duration;
import java.util.Timer;
import java.util.TimerTask;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.storage.annotation.AnnotationSupport;

import net.shibboleth.shared.annotation.OnTeardown;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.Positive;
import net.shibboleth.shared.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.TimerSupport;

/**
 * Abstract base class for {@link StorageService} implementations.
 * 
 * <p>
 * The base class handles support for a background cleanup task, and handles calling of custom object serializers.
 * </p>
 */
public abstract class AbstractStorageService extends AbstractIdentifiableInitializableComponent implements
        StorageService, StorageCapabilities {

    /** Time between cleanup checks. Default value: (0) */
    @Nonnull private Duration cleanupInterval;

    /** Timer used to schedule cleanup tasks. */
    @Nullable private Timer cleanupTaskTimer;

    /** Timer used to schedule cleanup tasks if no external one set. */
    @Nullable private Timer internalTaskTimer;

    /** Task that cleans up expired records. */
    @Nullable private TimerTask cleanupTask;

    /** Configurable context size limit. */
    @Positive private int contextSize;

    /** Configurable key size limit. */
    @Positive private int keySize;

    /** Configurable value size limit. */
    @Positive private int valueSize;
    
    /** Constructor. */
    public AbstractStorageService() {
        cleanupInterval = Duration.ZERO;
    }

    /**
     * Gets the time between one cleanup and another. A value of 0 indicates that no cleanup will be
     * performed.
     * 
     * @return time between one cleanup and another
     */
    @Nonnull public Duration getCleanupInterval() {
        return cleanupInterval;
    }

    /**
     * Sets the time between one cleanup and another. A value of 0 indicates that no cleanup will be
     * performed.
     * 
     * This setting cannot be changed after the service has been initialized.
     * 
     * @param interval time between one cleanup and another
     */
    public void setCleanupInterval(@Nonnull final Duration interval) {
        checkSetterPreconditions();
        
        Constraint.isNotNull(interval, "Interval cannot be null");
        Constraint.isFalse(interval.isNegative(), "Interval cannot be negative");

        cleanupInterval = interval;
    }

    /**
     * Gets the timer used to schedule cleanup tasks.
     * 
     * @return timer used to schedule cleanup tasks
     */
    @Nullable public Timer getCleanupTaskTimer() {
        return cleanupTaskTimer;
    }

    /**
     * Sets the timer used to schedule cleanup tasks.
     * 
     * This setting can not be changed after the service has been initialized.
     * 
     * @param timer timer used to schedule configuration reload tasks
     */
    public void setCleanupTaskTimer(@Nullable final Timer timer) {
        checkSetterPreconditions();

        cleanupTaskTimer = timer;
    }

    /**
     * Returns a cleanup task function to schedule for background cleanup.
     * 
     * <p>
     * The default implementation does not supply one.
     * </p>
     * 
     * @return a task object, or null
     */
    @Nullable protected TimerTask getCleanupTask() {
        return null;
    }

    /**
     * Set the context size limit.
     * 
     * @param size limit on context size in characters
     */
    public void setContextSize(@Positive final int size) {
        checkSetterPreconditions();

        contextSize = Constraint.isGreaterThan(0, size, "Size must be greater than zero");
    }

    /**
     * Set the key size limit.
     * 
     * @param size size limit on key size in characters
     */
    public void setKeySize(@Positive final int size) {
        checkSetterPreconditions();

        keySize = Constraint.isGreaterThan(0, size, "Size must be greater than zero");
    }

    /**
     * Set the value size limit.
     * 
     * @param size size limit on value size in characters
     */
    public void setValueSize(@Positive final int size) {
        checkSetterPreconditions();

        valueSize = Constraint.isGreaterThan(0, size, "Size must be greater than zero");
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (!cleanupInterval.isZero()) {
            cleanupTask = getCleanupTask();
            if (cleanupTask == null) {
                throw new ComponentInitializationException("Cleanup task cannot be null if cleanupInterval is set.");
            } else if (cleanupTaskTimer == null) {
                internalTaskTimer = new Timer(TimerSupport.getTimerName(this), true);
            } else {
                internalTaskTimer = cleanupTaskTimer;
            }
            assert internalTaskTimer != null;
            internalTaskTimer.schedule(cleanupTask, cleanupInterval.toMillis(), cleanupInterval.toMillis());
        }
    }

    /**
     * Tear down worker tasks when the containing service reloads.
     */
    @OnTeardown
    public final synchronized void teardownAbstractStorageService() {
        if (cleanupTask != null) {
            cleanupTask.cancel();
            cleanupTask = null;
            if (cleanupTaskTimer == null) {
                assert internalTaskTimer != null;
                internalTaskTimer.cancel();
            }
            internalTaskTimer = null;
        }
    }

    /** {@inheritDoc} */
    @Override @Nonnull public StorageCapabilities getCapabilities() {
        return this;
    }

    /** {@inheritDoc} */
    @Override public int getContextSize() {
        return contextSize;
    }

    /** {@inheritDoc} */
    @Override public int getKeySize() {
        return keySize;
    }

    /** {@inheritDoc} */
    @Override public long getValueSize() {
        return valueSize;
    }

    /** {@inheritDoc} */
    @Override
    public <T> boolean create(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key,
            @Nonnull final T value, @Nonnull final StorageSerializer<T> serializer,
            @Nullable @Positive final Long expiration) throws IOException {
        return create(context, key, serializer.serialize(value), expiration);
    }

    /** {@inheritDoc} */
    @Override public boolean create(@Nonnull final Object value) throws IOException {
        
        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        final String val = AnnotationSupport.getValue(value);
        if (context == null || key == null || val == null) {
            throw new IOException("Context, key, and value must be non-null");
        }
        
        return create(context, key, val, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    @Override @Nullable public Object read(@Nonnull final Object value) throws IOException {
        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }
        
        final StorageRecord<?> record = read(context, key);
        if (record != null) {
            AnnotationSupport.setValue(value, record.getValue());
            AnnotationSupport.setExpiration(value, record.getExpiration());
            return value;
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public <T> boolean update(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key,
            @Nonnull final T value, @Nonnull final StorageSerializer<T> serializer,
            @Nullable @Positive final Long expiration) throws IOException {
        return update(context, key, serializer.serialize(value), expiration);
    }

    /** {@inheritDoc} */
    // Checkstyle: ParameterNumber OFF
    @Override
    @Nullable public <T> Long updateWithVersion(@Positive final long version,
            @Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key, @Nonnull final T value,
            @Nonnull final StorageSerializer<T> serializer, @Nullable @Positive final Long expiration)
                    throws IOException, VersionMismatchException {
        return updateWithVersion(version, context, key, serializer.serialize(value), expiration);
    }

    // Checkstyle: ParameterNumber ON

    /** {@inheritDoc} */
    @Override public boolean update(@Nonnull final Object value) throws IOException {
        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        final String val = AnnotationSupport.getValue(value);
        if (context == null || key == null || val == null) {
            throw new IOException("Context, key, and value must be non-null");
        }
        
        return update(context, key, val, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    @Override @Nullable public Long updateWithVersion(@Positive final long version, @Nonnull final Object value)
            throws IOException, VersionMismatchException {
        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        final String val = AnnotationSupport.getValue(value);
        if (context == null || key == null || val == null) {
            throw new IOException("Context, key, and value must be non-null");
        }
        
        return updateWithVersion(version, context, key, val, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    @Override public boolean updateExpiration(@Nonnull final Object value) throws IOException {
        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }

        return updateExpiration(context, key, AnnotationSupport.getExpiration(value));
    }

    /** {@inheritDoc} */
    @Override public boolean delete(@Nonnull final Object value) throws IOException {
        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }

        return delete(context, key);
    }

    /** {@inheritDoc} */
    @Override public boolean deleteWithVersion(@Positive final long version, @Nonnull final Object value)
            throws IOException, VersionMismatchException {
        final String context = AnnotationSupport.getContext(value);
        final String key = AnnotationSupport.getKey(value);
        if (context == null || key == null) {
            throw new IOException("Context and key must be non-null");
        }
        
        return deleteWithVersion(version, context, key);
    }

}