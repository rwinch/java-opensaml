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
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.metrics.MetricsSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.persist.XMLObjectLoadSaveManager;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.core.xml.util.XMLObjectSupport.CloneOutputOption;
import org.opensaml.saml.metadata.resolver.ClearableMetadataResolver;
import org.opensaml.saml.metadata.resolver.DynamicMetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.index.MetadataIndex;
import org.opensaml.saml.metadata.resolver.index.impl.LockableMetadataIndexManager;
import org.opensaml.saml.saml2.common.SAML2Support;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.crypto.JCAConstants;
import org.slf4j.Logger;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.RatioGauge;
import com.codahale.metrics.Timer.Context;
import com.google.common.base.MoreObjects;

import net.shibboleth.shared.annotation.OnTeardown;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Positive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.codec.StringDigester;
import net.shibboleth.shared.codec.StringDigester.OutputFormat;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.ConstraintViolationException;
import net.shibboleth.shared.logic.PredicateSupport;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.primitive.TimerSupport;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * Abstract subclass for metadata resolvers that resolve metadata dynamically, as needed and on demand.
 */
public abstract class AbstractDynamicMetadataResolver extends AbstractMetadataResolver 
        implements DynamicMetadataResolver, ClearableMetadataResolver {
    
    /** Metric name for the timer for {@link #fetchFromOriginSource(CriteriaSet)}. */
    @Nonnull @NotEmpty public static final String METRIC_TIMER_FETCH_FROM_ORIGIN_SOURCE = "timer.fetchFromOriginSource";
    
    /** Metric name for the timer for {@link #resolve(CriteriaSet)}. */
    @Nonnull @NotEmpty public static final String METRIC_TIMER_RESOLVE = "timer.resolve";
    
    /** Metric name for the ratio gauge of fetches to resolve requests. */
    @Nonnull @NotEmpty public static final String METRIC_RATIOGAUGE_FETCH_TO_RESOLVE = "ratioGauge.fetchToResolve";
    
    /** Metric name for the gauge of the number of live entityIDs. */
    @Nonnull @NotEmpty public static final String METRIC_GAUGE_NUM_LIVE_ENTITYIDS = "gauge.numLiveEntityIDs";
    
    /** Metric name for the gauge of the persistent cache initialization metrics. */
    @Nonnull @NotEmpty
    public static final String METRIC_GAUGE_PERSISTENT_CACHE_INIT = "gauge.persistentCacheInitialization";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractDynamicMetadataResolver.class);
        
    /** Metrics Timer for {@link #resolve(CriteriaSet)}. */
    @Nullable private com.codahale.metrics.Timer timerResolve;
    
    /** Metrics Timer for {@link #fetchFromOriginSource(CriteriaSet)}. */
    @Nullable private com.codahale.metrics.Timer timerFetchFromOriginSource;
    
    /** Metrics RatioGauge for count of origin fetches to resolves.*/
    @Nullable private RatioGauge ratioGaugeFetchToResolve;
    
    /** Metrics Gauge for the number of live entityIDs.*/
    @Nullable private Gauge<Integer> gaugeNumLiveEntityIDs;
    
    /** Metrics Gauge for the persistent cache initialization.*/
    @Nullable private Gauge<PersistentCacheInitializationMetrics> gaugePersistentCacheInit;
    
    /** Timer used to schedule background metadata update tasks. */
    @NonnullAfterInit private Timer taskTimer;
    
    /** Whether we created our own task timer during object construction. */
    private boolean createdOwnTaskTimer;
    
    /** Minimum cache duration. */
    @Nonnull private Duration minCacheDuration;
    
    /** Maximum cache duration. */
    @Nonnull private Duration maxCacheDuration;
    
    /** Negative lookup cache duration. */
    @Nonnull private Duration negativeLookupCacheDuration;
    
    /** Factor used to compute when the next refresh interval will occur. Default value: 0.75 */
    @Positive @Nonnull private Float refreshDelayFactor;
    
    /** The maximum idle time for which the resolver will keep data for a given entityID, 
     * before it is removed. */
    @Nonnull private Duration maxIdleEntityData;
    
    /** Flag indicating whether idle entity data should be removed. */
    private boolean removeIdleEntityData;
    
    /** Impending expiration warning threshold for metadata refresh. 
     * Default value: 0 (disabled). */
    @Nonnull private Duration expirationWarningThreshold;
    
    /** The interval at which the cleanup task should run. */
    @Nonnull private Duration cleanupTaskInterval;
    
    /** The backing store cleanup sweeper background task. */
    private BackingStoreCleanupSweeper cleanupTask;
    
    /** The manager for the persistent cache store for resolved metadata. */
    @Nullable private XMLObjectLoadSaveManager<EntityDescriptor> persistentCacheManager;
    
    /** Function for generating the String key used with the cache manager. */
    @Nullable private Function<EntityDescriptor,String> persistentCacheKeyGenerator;
    
    /** Flag indicating whether should initialize from the persistent cache in the background. */
    private boolean initializeFromPersistentCacheInBackground;
    
    /** The delay after which to schedule the background initialization from the persistent cache. */
    @Nonnull private Duration backgroundInitializationFromCacheDelay;
    
    /** Predicate which determines whether a given entity should be loaded from the persistent cache
     * at resolver initialization time. */
    @Nullable private Predicate<EntityDescriptor> initializationFromCachePredicate;
    
    /** Object tracking metrics related to the persistent cache initialization. */
    @NonnullAfterInit private PersistentCacheInitializationMetrics persistentCacheInitMetrics;
    
    /** The set of indexes configured. */
    @Nonnull private Set<MetadataIndex> indexes;
    
    /** Flag used to track state of whether currently initializing or not. */
    private boolean initializing;
    
    /**
     * Constructor.
     *
     * @param backgroundTaskTimer the {@link Timer} instance used to run resolver background management tasks
     */
    public AbstractDynamicMetadataResolver(@Nullable final Timer backgroundTaskTimer) {
        indexes = CollectionSupport.emptySet();
        
        if (backgroundTaskTimer == null) {
            taskTimer = new Timer(TimerSupport.getTimerName(this), true);
            createdOwnTaskTimer = true;
        } else {
            taskTimer = backgroundTaskTimer;
        }
        
        expirationWarningThreshold = Duration.ZERO;
        
        minCacheDuration = Duration.ofMinutes(10);
        
        maxCacheDuration = Duration.ofHours(8);
        
        refreshDelayFactor = 0.75f;
        
        negativeLookupCacheDuration = Duration.ofMinutes(10);
        
        cleanupTaskInterval = Duration.ofMinutes(30);
        
        maxIdleEntityData = Duration.ofHours(8);
        
        // Default to removing idle metadata
        removeIdleEntityData = true;
        
        // Default to initializing from the the persistent cache in the background
        initializeFromPersistentCacheInBackground = true;
        
        backgroundInitializationFromCacheDelay = Duration.ofSeconds(2);
    }
    
    /**
     * Get the flag indicating whether should initialize from the persistent cache in the background.
     * 
     * <p>Defaults to: true.</p>
     * 
     * @return true if should init from the cache in background, false otherwise
     */
    public boolean isInitializeFromPersistentCacheInBackground() {
        return initializeFromPersistentCacheInBackground;
    }

    /**
     * Set the flag indicating whether should initialize from the persistent cache in the background.
     * 
     * <p>Defaults to: true.</p>
     * 
     * @param flag true if should init from the cache in the background, false otherwise
     */
    public void setInitializeFromPersistentCacheInBackground(final boolean flag) {
        checkSetterPreconditions();
        initializeFromPersistentCacheInBackground = flag;
    }

    /**
     * Get the delay after which to schedule the background initialization from the persistent cache.
     * 
     * <p>Defaults to: 2 seconds.</p>
     * 
     * @return the delay
     * 
     * @since 3.3.0
     */
    @Nonnull public Duration getBackgroundInitializationFromCacheDelay() {
        return backgroundInitializationFromCacheDelay;
    }

    /**
     * Set the delay after which to schedule the background initialization from the persistent cache.
     * 
     * <p>Defaults to: 2 seconds.</p>
     * 
     * @param delay the delay
     * 
     * @since 3.3.0
     */
    public void setBackgroundInitializationFromCacheDelay(@Nonnull final Duration delay) {
        checkSetterPreconditions();
        
        Constraint.isNotNull(delay, "Delay cannot be null");
        Constraint.isFalse(delay.isNegative(), "Delay cannot be negative");
        
        backgroundInitializationFromCacheDelay = delay;
        
    }

    /**
     * Get the manager for the persistent cache store for resolved metadata.
     * 
     * @return the cache manager if configured, or null
     */
    @Nullable public XMLObjectLoadSaveManager<EntityDescriptor> getPersistentCacheManager() {
        return persistentCacheManager;
    }

    /**
     * Get the manager for the persistent cache store for resolved metadata, raising a
     * {@link ConstraintViolationException} if null.
     * 
     * @return the cache manager if configured
     * 
     * @since 5.0.0
     */
    @Nonnull public XMLObjectLoadSaveManager<EntityDescriptor> ensurePersistentCacheManager() {
        return Constraint.isNotNull(persistentCacheManager, "Persistent cache manager was null");
    }

    /**
     * Set the manager for the persistent cache store for resolved metadata.
     * 
     * @param manager the cache manager, may be null
     */
    public void setPersistentCacheManager(@Nullable final XMLObjectLoadSaveManager<EntityDescriptor> manager) {
        checkSetterPreconditions();
        persistentCacheManager = manager;
    }
    
    /**
     * Get the flag indicating whether persistent caching of the resolved metadata is enabled.
     * 
     * @return true if enabled, false otherwise
     */
    public boolean isPersistentCachingEnabled() {
        return getPersistentCacheManager() != null;
    }

    /**
     * Get the function for generating the String key used with the persistent cache manager. 
     * 
     * @return the key generator or null
     */
    @NonnullAfterInit public Function<EntityDescriptor, String> getPersistentCacheKeyGenerator() {
        return persistentCacheKeyGenerator;
    }

    /**
     * Set the function for generating the String key used with the persistent cache manager. 
     * 
     * @param generator the new generator to set, may be null
     */
    public void setPersistentCacheKeyGenerator(@Nullable final Function<EntityDescriptor, String> generator) {
        checkSetterPreconditions();
        persistentCacheKeyGenerator = generator;
    }

    /**
     * Get the predicate which determines whether a given entity should be loaded from the persistent cache
     * at resolver initialization time.
     * 
     * @return the cache initialization predicate
     */
    @NonnullAfterInit public Predicate<EntityDescriptor> getInitializationFromCachePredicate() {
        return initializationFromCachePredicate;
    }

    /**
     * Set the predicate which determines whether a given entity should be loaded from the persistent cache
     * at resolver initialization time.
     * 
     * @param predicate the cache initialization predicate
     */
    public void setInitializationFromCachePredicate(@Nullable final Predicate<EntityDescriptor> predicate) {
        checkSetterPreconditions();
        initializationFromCachePredicate = predicate;
    }

    /**
     *  Get the minimum cache duration for metadata.
     *  
     *  <p>Defaults to: 10 minutes.</p>
     *  
     * @return the minimum cache duration
     */
    @Nonnull public Duration getMinCacheDuration() {
        return minCacheDuration;
    }

    /**
     *  Set the minimum cache duration for metadata.
     *  
     *  <p>Defaults to: 10 minutes.</p>
     *  
     * @param duration the minimum cache duration
     */
    public void setMinCacheDuration(@Nonnull final Duration duration) {
        checkSetterPreconditions();

        Constraint.isNotNull(duration, "Duration cannot be null");
        Constraint.isFalse(duration.isNegative(), "Duration cannot be negative");
        
        minCacheDuration = duration;
    }

    /**
     *  Get the maximum cache duration for metadata.
     *  
     *  <p>Defaults to: 8 hours.</p>
     *  
     * @return the maximum cache duration
     */
    @Nonnull public Duration getMaxCacheDuration() {
        return maxCacheDuration;
    }

    /**
     *  Set the maximum cache duration for metadata.
     *  
     *  <p>Defaults to: 8 hours.</p>
     *  
     * @param duration the maximum cache duration
     */
    public void setMaxCacheDuration(@Nonnull final Duration duration) {
        checkSetterPreconditions();

        Constraint.isNotNull(duration, "Duration cannot be null");
        Constraint.isFalse(duration.isNegative(), "Duration cannot be negative");
        
        maxCacheDuration = duration;
    }
    
    /**
     *  Get the negative lookup cache duration for metadata.
     *  
     *  <p>Defaults to: 10 minutes.</p>
     *  
     * @return the negative lookup cache duration
     */
    @Nonnull public Duration getNegativeLookupCacheDuration() {
        return negativeLookupCacheDuration;
    }

    /**
     *  Set the negative lookup cache duration for metadata.
     *  
     *  <p>Defaults to: 10 minutes.</p>
     *  
     * @param duration the negative lookup cache duration
     */
    public void setNegativeLookupCacheDuration(@Nonnull final Duration duration) {
        checkSetterPreconditions();

        Constraint.isNotNull(duration, "Duration cannot be null");
        Constraint.isFalse(duration.isNegative(), "Duration cannot be negative");
        
        negativeLookupCacheDuration = duration;
    }
    
    /**
     * Gets the delay factor used to compute the next refresh time.
     * 
     * <p>Defaults to:  0.75.</p>
     * 
     * @return delay factor used to compute the next refresh time
     */
    @Nonnull public Float getRefreshDelayFactor() {
        return refreshDelayFactor;
    }

    /**
     * Sets the delay factor used to compute the next refresh time. The delay must be between 0.0 and 1.0, exclusive.
     * 
     * <p>Defaults to:  0.75.</p>
     * 
     * @param factor delay factor used to compute the next refresh time
     */
    public void setRefreshDelayFactor(@Nonnull final Float factor) {
        checkSetterPreconditions();

        if (factor <= 0 || factor >= 1) {
            throw new IllegalArgumentException("Refresh delay factor must be a number between 0.0 and 1.0, exclusive");
        }

        refreshDelayFactor = factor;
    }

    /**
     * Get the flag indicating whether idle entity data should be removed. 
     * 
     * @return true if idle entity data should be removed, false otherwise
     */
    public boolean isRemoveIdleEntityData() {
        return removeIdleEntityData;
    }

    /**
     * Set the flag indicating whether idle entity data should be removed. 
     * 
     * @param flag true if idle entity data should be removed, false otherwise
     */
    public void setRemoveIdleEntityData(final boolean flag) {
        checkSetterPreconditions();
        removeIdleEntityData = flag;
    }

    /**
     * Get the maximum idle time for which the resolver will keep data for a given entityID, 
     * before it is removed.
     * 
     * <p>Defaults to: 8 hours.</p>
     * 
     * @return return the maximum idle time
     */
    @Nonnull public Duration getMaxIdleEntityData() {
        return maxIdleEntityData;
    }

    /**
     * Set the maximum idle time for which the resolver will keep data for a given entityID, 
     * before it is removed.
     * 
     * <p>Defaults to: 8 hours.</p>
     * 
     * @param max the maximum entity data idle time
     */
    public void setMaxIdleEntityData(@Nonnull final Duration max) {
        checkSetterPreconditions();

        Constraint.isNotNull(max, "Max idle time cannot be null");
        Constraint.isFalse(max.isNegative(), "Max idle time cannot be negative");

        maxIdleEntityData = max;
    }
    
    /**
     * Gets the impending expiration warning threshold used at refresh time.
     * 
     * @return threshold for logging a warning if live metadata will soon expire
     */
    @Nonnull public Duration getExpirationWarningThreshold() {
        return expirationWarningThreshold;
    }

    /**
     * Sets the impending expiration warning threshold used at refresh time.
     * 
     * @param threshold the threshold for logging a warning if live metadata will soon expire
     */
    public void setExpirationWarningThreshold(@Nullable final Duration threshold) {
        checkSetterPreconditions();
        
        if (threshold == null) {
            expirationWarningThreshold = Duration.ZERO;
        } else if (threshold.isNegative()) {
            throw new IllegalArgumentException("Expiration warning threshold must be greater than or equal to 0");
        } else {
            expirationWarningThreshold = threshold;
        }
    }

    /**
     * Get the interval at which the cleanup task should run.
     * 
     * <p>Defaults to: 30 minutes.</p>
     * 
     * @return return the interval
     */
    @Nonnull public Duration getCleanupTaskInterval() {
        return cleanupTaskInterval;
    }

    /**
     * Set the interval at which the cleanup task should run.
     * 
     * <p>Defaults to: 30 minutes.</p>
     * 
     * @param interval the interval to set
     */
    public void setCleanupTaskInterval(@Nonnull final Duration interval) {
        checkSetterPreconditions();
        
        Constraint.isNotNull(interval, "Cleanup task interval may not be null");
        Constraint.isFalse(interval.isNegative() || interval.isZero(), "Cleanup task interval must be positive");
        
        cleanupTaskInterval = interval;
    }
    
    /**
     * Get the configured indexes.
     * 
     * @return the set of configured indexes
     */
    @Nonnull @Unmodifiable @NotLive public Set<MetadataIndex> getIndexes() {
        return indexes;
    }

    /**
     * Set the configured indexes.
     * 
     * @param newIndexes the new indexes to set
     */
    public void setIndexes(@Nullable final Set<MetadataIndex> newIndexes) {
        checkSetterPreconditions();

        if (newIndexes == null) {
            indexes = CollectionSupport.emptySet();
        } else {
            indexes = CollectionSupport.copyToSet(newIndexes);
        }
    }
    
    /**
     * Return whether secondary indexing is effectively active.
     * 
     * @return true if active, false if not.
     */
    protected boolean indexesEnabled() {
        return !ensureBackingStore().getSecondaryIndexManager().getIndexes().isEmpty();
    }
    
    /** {@inheritDoc} */
    public void clear() throws ResolverException {
        final DynamicEntityBackingStore backingStore = ensureBackingStore();
        final Set<String> entityIDs = new HashSet<>();
        entityIDs.addAll(backingStore.getIndexedDescriptors().keySet());
        entityIDs.addAll(backingStore.getManagementDataEntityIDs());
        
        for (final String entityID : entityIDs) {
            assert entityID != null;
            clear(entityID);
        }
    }

    /** {@inheritDoc} */
    public void clear(@Nonnull final String entityID) throws ResolverException {
        final DynamicEntityBackingStore backingStore = ensureBackingStore();
        final EntityManagementData mgmtData = backingStore.getManagementData(entityID);
        final Lock writeLock = mgmtData.getReadWriteLock().writeLock();
        try {
            writeLock.lock();

            removeByEntityID(entityID, backingStore);
            backingStore.removeManagementData(entityID);

        } finally {
            writeLock.unlock();
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected Iterable<EntityDescriptor> doResolve(@Nullable final CriteriaSet criteria)
            throws ResolverException {
        checkComponentActive();
        if (cleanupTask == null) {
            log.warn("{} Called doResolve in a torn down resolver", getId());
        }
        
        final Context contextResolve = MetricsSupport.startTimer(timerResolve);
        try {
            Iterable<EntityDescriptor> candidates = null;
            
            final String entityID = resolveEntityID(criteria);
            if (entityID != null) {
                log.debug("{} Resolved criteria to entityID: {}", getLogPrefix(), entityID);

                final EntityManagementData mgmtData = ensureBackingStore().getManagementData(entityID);
                final Lock readLock = mgmtData.getReadWriteLock().readLock();
                try {
                    readLock.lock();

                    final List<EntityDescriptor> descriptors = lookupEntityID(entityID);
                    if (descriptors.isEmpty()) {
                        if (mgmtData.isNegativeLookupCacheActive()) {
                            log.debug("{} Did not find requested metadata in backing store, " 
                                    + "and negative lookup cache is active, returning empty result", 
                                    getLogPrefix());
                            return CollectionSupport.emptyList();
                        }
                        log.debug("{} Did not find requested metadata in backing store, " 
                                + "attempting to resolve dynamically", 
                                getLogPrefix());
                    } else {
                        if (shouldAttemptRefresh(mgmtData)) {
                            log.debug("{} Metadata was indicated to be refreshed based on refresh trigger time", 
                                    getLogPrefix());
                        } else {
                            log.debug("{} Found requested metadata in backing store", getLogPrefix());
                            candidates = descriptors;
                        }
                    }
                } finally {
                    readLock.unlock();
                }
            } else {
                log.debug("{} Single entityID unresolveable from criteria, will resolve from origin by criteria only",
                        getLogPrefix());
            }

            if (candidates == null) {
                candidates = resolveFromOriginSource(criteria, entityID);
            }

            return predicateFilterCandidates(candidates, criteria, false);
        } finally {
            MetricsSupport.stopTimer(contextResolve);
        }
    }
    
    /**
    * Attempt to resolve the single entityID for the operation from the criteria set.
    * 
    * <p>
    * If an {@link EntityIdCriterion} is present, that will be used. If not present, then a single
    * entityID will be resolved via the secondary index manager of the backing store.
    * </p>
    * 
    * @param criteria the criteria set on which to operate
    * @return the resolve entityID, or null if a single entityID could not be resolved
    */
    @Nullable protected String resolveEntityID(@Nullable final CriteriaSet criteria) {
        final Set<String> entityIDs = resolveEntityIDs(criteria);
        if (entityIDs.size() == 1) {
            return entityIDs.iterator().next();
        }
        return null;
    }
    
    /**
    * 
    * Attempt to resolve all the entityIDs represented by the criteria set.
    * 
    * <p>
    * If an {@link EntityIdCriterion} is present, that will be used. If not present, then 
    * entityIDs will be resolved via the secondary index manager of the backing store.
    * </p>
    * 
    * @param criteria the criteria set on which to operate
    * @return the resolved entityIDs, may be empty
    */
    @Nonnull protected Set<String> resolveEntityIDs(@Nullable final CriteriaSet criteria) {
        final EntityIdCriterion entityIdCriterion = criteria != null ? criteria.get(EntityIdCriterion.class) : null;
        if (entityIdCriterion != null) {
            log.debug("{} Found entityID in criteria: {}", getLogPrefix(), entityIdCriterion.getEntityId());
            return CollectionSupport.singleton(entityIdCriterion.getEntityId());
        }
        log.debug("{} EntityID was not supplied in criteria, processing criteria with secondary indexes",
                getLogPrefix());
        
        if (!indexesEnabled()) {
            log.trace("Indexes not enabled, skipping secondary index processing");
            return CollectionSupport.emptySet();
        }

        Optional<Set<String>> indexedResult = Optional.empty();
        final Lock readLock = ensureBackingStore().getSecondaryIndexManager().getReadWriteLock().readLock();
        try {
            readLock.lock();
            indexedResult = ensureBackingStore().getSecondaryIndexManager().lookupIndexedItems(criteria);
        } finally {
            readLock.unlock();
        }

        if (indexedResult.isPresent()) {
            final Set<String> entityIDs = indexedResult.get();
            if (entityIDs.isEmpty()) {
                log.debug("{} No entityIDs resolved from secondary indexes (Optional 'present' with empty set)",
                        getLogPrefix());
                return CollectionSupport.emptySet();
            } else if (entityIDs.size() > 1) {
                log.debug("{} Multiple entityIDs resolved from secondary indexes: {}", 
                        getLogPrefix(), entityIDs);
                return new HashSet<>(entityIDs);
            } else {
                final String entityID = entityIDs.iterator().next();
                assert entityID != null;
                log.debug("{} Resolved 1 entityID from secondary indexes: {}", getLogPrefix(), entityID);
                return CollectionSupport.singleton(entityID);
            }
        }
        log.debug("{} No entityIDs resolved from secondary indexes (Optional 'absent').", getLogPrefix());
        return CollectionSupport.emptySet();
    }
    
    /**
     * Fetch metadata from an origin source based on the input criteria, store it in the backing store 
     * and then return it.
     * 
     * @param criteria the input criteria set
     * @param entityID the previously resolved single entityID
     * @return the resolved metadata
     * @throws ResolverException  if there is a fatal error attempting to resolve the metadata
     */
    @Nonnull protected Iterable<EntityDescriptor> resolveFromOriginSource(@Nullable final CriteriaSet criteria,
            @Nullable final String entityID) throws ResolverException {
        
        if (entityID != null) {
            log.debug("{} Resolving from origin source based on entityID: {}", getLogPrefix(), entityID);
            return resolveFromOriginSourceWithEntityID(criteria, entityID);
        }
        log.debug("{} Resolving from origin source based on non-entityID criteria", getLogPrefix());
        return resolveFromOriginSourceWithoutEntityID(criteria);
        
    }
 
    /**
     * Fetch metadata from an origin source based on the input criteria when the entityID is known,
     * store it in the backing store and then return it.
     * 
     * @param criteria the input criteria set
     * @param entityID the entityID known to be represented by the criteria set
     * @return the resolved metadata
     * @throws ResolverException  if there is a fatal error attempting to resolve the metadata
     */
    @Nonnull protected Iterable<EntityDescriptor> resolveFromOriginSourceWithEntityID(
            @Nullable final CriteriaSet criteria, @Nonnull final String entityID) throws ResolverException {
        
        final EntityManagementData mgmtData = ensureBackingStore().getManagementData(entityID);
        final Lock writeLock = mgmtData.getReadWriteLock().writeLock(); 
        
        try {
            writeLock.lock();
            
            // It's possible that multiple threads fall into here and attempt to preemptively refresh. 
            // This check should ensure that only 1 actually successfully does it, b/c the refresh
            // trigger time will be updated as seen by the subsequent ones. 
            final List<EntityDescriptor> descriptors = lookupEntityID(entityID);
            if (!descriptors.isEmpty() && !shouldAttemptRefresh(mgmtData)) {
                log.debug("{} Metadata was resolved and stored by another thread " 
                        + "while this thread was waiting on the write lock", getLogPrefix());
                return descriptors;
            }
            log.debug("{} Resolving metadata dynamically for entity ID: {}", getLogPrefix(), entityID);
            
            final Context contextFetchFromOriginSource = MetricsSupport.startTimer(timerFetchFromOriginSource);
            XMLObject root = null;
            try {
                root = fetchFromOriginSource(criteria);
            } finally {
                MetricsSupport.stopTimer(contextFetchFromOriginSource);
            }
            
            if (root == null) {
                mgmtData.initNegativeLookupCache();
                log.debug("{} No metadata was fetched from the origin source", getLogPrefix());

                if (!descriptors.isEmpty()) {
                    mgmtData.setRefreshTriggerTime(computeRefreshTriggerTime(mgmtData.getExpirationTime(), 
                            Instant.now()));
                    log.debug("{} Had existing data, recalculated refresh trigger time as: {}", 
                            getLogPrefix(), mgmtData.getRefreshTriggerTime());
                }
            } else {
                mgmtData.clearNegativeLookupCache();
                try {
                    processNewMetadata(root, entityID);
                } catch (final FilterException e) {
                    log.error("{} Metadata filtering problem processing new metadata", getLogPrefix(), e);
                }
            }
            
            return lookupEntityID(entityID);
            
        } catch (final IOException e) {
            log.error("{} Error fetching metadata from origin source", getLogPrefix(), e);
            return lookupEntityID(entityID);
        } finally {
            writeLock.unlock();
        }
        
    }
    
    /**
     * Fetch metadata from an origin source based on the input criteria when the entityID is not known,
     * store it in the backing store and then return it.
     * 
     * @param criteria the input criteria set
     * @return the resolved metadata
     * @throws ResolverException if there is a fatal error attempting to resolve the metadata
     */
    @Nonnull protected Iterable<EntityDescriptor> resolveFromOriginSourceWithoutEntityID(@Nullable final CriteriaSet criteria) 
            throws ResolverException {
        
        XMLObject root = null;
        final Context contextFetchFromOriginSource = MetricsSupport.startTimer(timerFetchFromOriginSource);
        try {
            root = fetchFromOriginSource(criteria);
        } catch (final IOException e) {
            log.error("{} Error fetching metadata from origin source", getLogPrefix(), e);
            return lookupCriteria(criteria);
        } finally {
            MetricsSupport.stopTimer(contextFetchFromOriginSource);
        }
        
        if (root == null) {
            log.debug("{} No metadata was fetched from the origin source", getLogPrefix());
            return lookupCriteria(criteria);
        } else if (root instanceof EntityDescriptor entity){
            log.debug("{} Fetched EntityDescriptor from the origin source", getLogPrefix());
            return processNonEntityIDFetchedEntityDescriptor(entity);
        } else if (root instanceof EntitiesDescriptor entities) {
            log.debug("{} Fetched EntitiesDescriptor from the origin source", getLogPrefix());
            return processNonEntityIDFetchedEntittiesDescriptor(entities);
        } else {
            log.warn("{} Fetched metadata was of an unsupported type: {}", getLogPrefix(), root.getClass().getName());
            return lookupCriteria(criteria);
        }
    }
    
    /**
     * Lookup and return all EntityDescriptors currently available in the resolver cache 
     * which match either entityID or secondary-indexed criteria.
     * 
     * @param criteria the input criteria set
     * @return the resolved metadata
     * @throws ResolverException if there is a fatal error attempting to resolve the metadata
     */
    @Nonnull protected Iterable<EntityDescriptor> lookupCriteria(@Nullable final CriteriaSet criteria) throws ResolverException {
        final List<EntityDescriptor> entities = new ArrayList<>();
        final Set<String> entityIDs = resolveEntityIDs(criteria);
        for (final String entityID : entityIDs) {
            assert entityID != null;
            final EntityManagementData mgmtData = ensureBackingStore().getManagementData(entityID);
            final Lock readLock = mgmtData.getReadWriteLock().readLock();
            try {
                readLock.lock();
                
                entities.addAll(lookupEntityID(entityID));
            } finally {
               readLock.unlock(); 
            }
        }
        return entities;
    }
    
    /**
     * Process an EntitiesDescriptor received from a non-entityID-based fetch.
     * 
     * @param entities the metadata to process
     * @return the resolved descriptor(s)
     * @throws ResolverException if there is a fatal error attempting to resolve the metadata
     */
    @Nonnull protected List<EntityDescriptor> processNonEntityIDFetchedEntittiesDescriptor(
            @Nonnull final EntitiesDescriptor entities) throws ResolverException {
        
        final List<EntityDescriptor> returnedEntities = new ArrayList<>();
        
        for (final EntitiesDescriptor childEntities : entities.getEntitiesDescriptors()) {
            assert childEntities != null;
            returnedEntities.addAll(processNonEntityIDFetchedEntittiesDescriptor(childEntities));
        }
        
        for (final EntityDescriptor entity : entities.getEntityDescriptors()) {
            assert entity != null;
            returnedEntities.addAll(processNonEntityIDFetchedEntityDescriptor(entity));
        }
        
        return returnedEntities;
    }
    
    /**
     * Process an EntityDescriptor received from a non-entityID-based fetch.
     * 
     * @param entity the metadata to process
     * @return the resolved descriptor(s)
     * @throws ResolverException if there is a fatal error attempting to resolve the metadata
     */
    @Nonnull protected List<EntityDescriptor> processNonEntityIDFetchedEntityDescriptor(
            @Nonnull final EntityDescriptor entity) throws ResolverException {
        
        final String entityID = entity.getEntityID();
        if (entityID == null) {
            throw new ResolverException("EntityDescriptor contained null entityID");
        }
        final EntityManagementData mgmtData = ensureBackingStore().getManagementData(entityID);
        final Lock writeLock = mgmtData.getReadWriteLock().writeLock(); 
        try {
            writeLock.lock();            
            mgmtData.clearNegativeLookupCache();
            processNewMetadata(entity, entityID);
            return lookupEntityID(entityID);
        } catch (final FilterException e) {
            log.error("{} Metadata filtering problem processing non-entityID fetched EntityDescriptor", 
                    getLogPrefix(), e);
            return lookupEntityID(entityID);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Fetch the metadata from the origin source.
     * 
     * @param criteria the input criteria set
     * @return the resolved metadata root XMLObject, or null if metadata could not be fetched
     * @throws IOException if there is a fatal error fetching metadata from the origin source
     */
    @Nullable protected abstract XMLObject fetchFromOriginSource(@Nullable final CriteriaSet criteria) 
            throws IOException;

    /** {@inheritDoc} */
    @Override
    @Nonnull protected List<EntityDescriptor> lookupEntityID(@Nonnull final String entityID) throws ResolverException {
        ensureBackingStore().getManagementData(entityID).recordEntityAccess();
        return super.lookupEntityID(entityID);
    }

    /**
     * Process the specified new metadata document, including metadata filtering, and store the 
     * processed metadata in the backing store.
     * 
     * <p>
     * Equivalent to {@link #processNewMetadata(XMLObject, String, boolean)} called with false.
     * </p>
     * 
     * @param root the root of the new metadata document being processed
     * @param expectedEntityID the expected entityID of the resolved metadata
     * 
     * @throws FilterException if there is a problem filtering the metadata
     */
    protected void processNewMetadata(@Nonnull final XMLObject root, @Nonnull final String expectedEntityID)
            throws FilterException {
        try {
            processNewMetadata(root, expectedEntityID, false);
        } catch (final ResolverException e) {
            //TODO this is kludgy, but necessary until we can change the API to add an exception to the method signature
            throw new FilterException(e);
        }
    }
    
    /**
     * Process the specified new metadata document, including metadata filtering, and store the 
     * processed metadata in the backing store.
     * 
     * <p>
     * In order to be processed successfully, the metadata (after filtering) must be an instance of
     * {@link EntityDescriptor} and its <code>entityID</code> value must match the value supplied
     * as the required <code>expectedEntityID</code> argument.
     * </p>
     * 
     * @param root the root of the new metadata document being processed
     * @param expectedEntityID the expected entityID of the resolved metadata
     * @param fromPersistentCache whether the entity data was loaded from the persistent cache
     * 
     * @throws FilterException if there is a problem filtering the metadata
     * @throws ResolverException if there is a problem processing the metadata
     */
    //CheckStyle: ReturnCount|CyclomaticComplexity OFF
    protected void processNewMetadata(@Nonnull final XMLObject root, @Nonnull final String expectedEntityID,
            final boolean fromPersistentCache) throws FilterException, ResolverException {
        
        final XMLObject filteredMetadata = filterMetadata(prepareForFiltering(root));
        
        if (filteredMetadata == null) {
            log.info("{} Metadata filtering process produced a null document, resulting in an empty data set", 
                    getLogPrefix());
            releaseMetadataDOM(root);
            if (fromPersistentCache) {
                throw new FilterException("Metadata filtering process produced a null XMLObject");
            }
            return;
        }
        
        if (filteredMetadata instanceof EntityDescriptor) {
            final EntityDescriptor entityDescriptor = (EntityDescriptor) filteredMetadata;
            if (!Objects.equals(entityDescriptor.getEntityID(), expectedEntityID)) {
                log.warn("{} New metadata's entityID '{}' does not match expected entityID '{}', will not process", 
                        getLogPrefix(), entityDescriptor.getEntityID(), expectedEntityID);
                if (fromPersistentCache) {
                    throw new ResolverException("New metadata's entityID does not match expected entityID");
                }
                return;
            }
            
            preProcessEntityDescriptor(entityDescriptor, ensureBackingStore());
            
            log.info("{} Successfully loaded new EntityDescriptor with entityID '{}' from {}",
                    getLogPrefix(), entityDescriptor.getEntityID(), 
                    fromPersistentCache ? "persistent cache" : "origin source");
            
            // Note: we store in the cache the original input XMLObject, not the filtered one
            if (isPersistentCachingEnabled() && !fromPersistentCache
                    && root instanceof EntityDescriptor origDescriptor) {
                final String key = getPersistentCacheKeyGenerator().apply(origDescriptor);
                log.trace("{} Storing resolved EntityDescriptor '{}' in persistent cache with key '{}'", 
                        getLogPrefix(), origDescriptor.getEntityID(), key);
                if (key == null) {
                    log.warn("{} Could not generate cache storage key for EntityDescriptor '{}', skipping caching", 
                            getLogPrefix(), origDescriptor.getEntityID());
                } else {
                    try {
                        ensurePersistentCacheManager().save(key, origDescriptor, true);
                    } catch (final IOException e) {
                        log.warn("{} Error saving EntityDescriptor '{}' to cache store with key {}'", 
                                getLogPrefix(), origDescriptor.getEntityID(), key);
                    }
                }
            }
            
        } else {
            log.warn("{} Document root was not an EntityDescriptor: {}", getLogPrefix(), root.getClass().getName());
        }
        
        releaseMetadataDOM(filteredMetadata);
        releaseMetadataDOM(root);
    
    }
    //CheckStyle: ReturnCount|CyclomaticComplexity ON
    
    /**
     * Prepare the object for filtering:  If persistent caching is enabled, return a clone of the object
     * in case the configured filter mutates the object.
     * 
     * @param input the XMLObject on which to operate
     * @return the XMLObject instance to be filtered
     */
    @Nonnull protected XMLObject prepareForFiltering(@Nonnull final XMLObject input) {
        if (getMetadataFilter() != null && isPersistentCachingEnabled()) {
            // For this case, we want to filter a clone of the input root object, since filters can mutate
            // the XMLObject and this will cause DOM to be dropped. This will muck with the persistent cache if
            //   1) the root doesn't expose its source byte[] via object metadata, and
            //   2) the object can't be successfully round-tripped (e.g signatures).
            try {
                return XMLObjectSupport.cloneXMLObject(input, CloneOutputOption.RootDOMInNewDocument);
            } catch (final MarshallingException | UnmarshallingException e) {
                log.warn("{} Error cloning XMLObject, will use input root object as filter target", getLogPrefix(), e);
                return input;
            }
        }
        return input;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void preProcessEntityDescriptor(@Nonnull final EntityDescriptor entityDescriptor, 
            @Nonnull final EntityBackingStore backingStore) {
        
        final String entityID = StringSupport.trimOrNull(entityDescriptor.getEntityID());
        assert entityID != null;
        
        removeByEntityID(entityID, backingStore);
        
        super.preProcessEntityDescriptor(entityDescriptor, backingStore);
        
        final DynamicEntityBackingStore dynamicBackingStore = (DynamicEntityBackingStore) backingStore;
        final EntityManagementData mgmtData = dynamicBackingStore.getManagementData(entityID);
        
        final Instant now = Instant.now();
        log.debug("{} For metadata expiration and refresh computation, 'now' is : {}", getLogPrefix(), now);
        
        mgmtData.setLastUpdateTime(now);
        
        mgmtData.setExpirationTime(computeExpirationTime(entityDescriptor, now));
        log.debug("{} Computed metadata expiration time: {}", getLogPrefix(), mgmtData.getExpirationTime());
        
        mgmtData.setRefreshTriggerTime(computeRefreshTriggerTime(mgmtData.getExpirationTime(), now));
        log.debug("{} Computed refresh trigger time: {}", getLogPrefix(), mgmtData.getRefreshTriggerTime());
        
        logMetadataExpiration(entityDescriptor, now, mgmtData.getRefreshTriggerTime());
    }
    
    /**
     * Check metadata for expiration or pending expiration and log appropriately.
     *
     * @param descriptor the entity descriptor being processes
     * @param now the current date/time
     * @param nextRefresh  the next refresh trigger time for the entity descriptor
     */
    private void logMetadataExpiration(@Nonnull final EntityDescriptor descriptor,
            @Nonnull final Instant now, @Nonnull final Instant nextRefresh) {
        if (!isValid(descriptor)) {
            log.warn("{} Metadata with ID '{}' currently live is expired or otherwise invalid",
                    getLogPrefix(), descriptor.getEntityID());
        } else {
            if (isRequireValidMetadata()) {
                final Instant validUntil = descriptor.getValidUntil();
                if (validUntil != null) {
                    if (!getExpirationWarningThreshold().isZero() 
                            && validUntil.isBefore(now.plus(getExpirationWarningThreshold()))) {
                        log.warn("{} Metadata with ID '{}' currently live will expire "
                                + "within the configured threshhold at '{}'",
                                getLogPrefix(), descriptor.getEntityID(), descriptor.getValidUntil());
                    } else if (validUntil.isBefore(nextRefresh)) {
                        log.warn("{} Metadata with ID '{}' currently live will expire "
                                + "at '{}' before the next refresh scheduled for {}'",
                                getLogPrefix(), descriptor.getEntityID(), descriptor.getValidUntil(), nextRefresh);
                    }
                }
            }
        }
    }

    /**
     * Compute the effective expiration time for the specified metadata.
     * 
     * @param entityDescriptor the EntityDescriptor instance to evaluate
     * @param now the current date time instant
     * @return the effective expiration time for the metadata
     */
    @Nonnull protected Instant computeExpirationTime(@Nonnull final EntityDescriptor entityDescriptor,
            @Nonnull final Instant now) {
        
        final Instant lowerBound = now.plus(getMinCacheDuration());
        
        Instant expiration = SAML2Support.getEarliestExpiration(entityDescriptor, now.plus(getMaxCacheDuration()), now);
        if (expiration == null || expiration.isBefore(lowerBound)) {
            expiration = lowerBound;
        }
        
        assert expiration != null;
        return expiration;
    }
    
    /**
     * Compute the refresh trigger time.
     * 
     * @param expirationTime the time at which the metadata effectively expires
     * @param nowDateTime the current date time instant
     * 
     * @return the time after which refresh attempt(s) should be made
     */
    @Nonnull protected Instant computeRefreshTriggerTime(@Nullable final Instant expirationTime,
            @Nonnull final Instant nowDateTime) {
        
        final long now = nowDateTime.toEpochMilli();

        long expireInstant = 0;
        if (expirationTime != null) {
            expireInstant = expirationTime.toEpochMilli();
        }
        long refreshDelay = (long) ((expireInstant - now) * getRefreshDelayFactor());

        // if the expiration time was null or the calculated refresh delay was less than the floor
        // use the floor
        if (refreshDelay < getMinCacheDuration().toMillis()) {
            refreshDelay = getMinCacheDuration().toMillis();
        }

        return nowDateTime.plusMillis(refreshDelay);
    }
    
    /**
     * Determine whether should attempt to refresh the metadata, based on stored refresh trigger time.
     * 
     * @param mgmtData the entity'd management data
     * @return true if should attempt refresh, false otherwise
     */
    protected boolean shouldAttemptRefresh(@Nonnull final EntityManagementData mgmtData) {
        return Instant.now().isAfter(mgmtData.getRefreshTriggerTime());
        
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected DynamicEntityBackingStore createNewBackingStore() {
        return new DynamicEntityBackingStore(getIndexes());
    }
    
    /** {@inheritDoc} */
    @Override
    @Nullable protected DynamicEntityBackingStore getBackingStore() {
        return (DynamicEntityBackingStore) super.getBackingStore();
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected DynamicEntityBackingStore ensureBackingStore() {
        return (DynamicEntityBackingStore) super.ensureBackingStore();
    }

    /** {@inheritDoc} */
    @Override
    protected void initMetadataResolver() throws ComponentInitializationException {
        try {
            initializing = true;
            
            super.initMetadataResolver();
            
            initializeMetricsInstrumentation();
            
            setBackingStore(createNewBackingStore());
            
            if (getPersistentCacheKeyGenerator() == null) {
                setPersistentCacheKeyGenerator(new DefaultCacheKeyGenerator());
            }
            
            if (getInitializationFromCachePredicate() == null) {
                setInitializationFromCachePredicate(PredicateSupport.alwaysTrue());
            }
            
            persistentCacheInitMetrics = new PersistentCacheInitializationMetrics();
            if (isPersistentCachingEnabled()) {
                persistentCacheInitMetrics.enabled = true;
                if (isInitializeFromPersistentCacheInBackground()) {
                    log.debug("{} Initializing from the persistent cache in the background in {} ms", 
                            getLogPrefix(), getBackgroundInitializationFromCacheDelay());
                    final TimerTask initTask = new TimerTask() {
                        public void run() {
                            initializeFromPersistentCache();
                        }
                    };
                    taskTimer.schedule(initTask, getBackgroundInitializationFromCacheDelay().toMillis());
                } else {
                    log.debug("{} Initializing from the persistent cache in the foreground", getLogPrefix());
                    initializeFromPersistentCache();
                }
            }
            
            cleanupTask = new BackingStoreCleanupSweeper();
            // Start with a delay of 1 minute, run at the user-specified interval
            taskTimer.schedule(cleanupTask, 1*60*1000, getCleanupTaskInterval().toMillis());

        } finally {
            initializing = false;
        }
    }

    /**
     * Initialize the Metrics-based instrumentation.
     */
    private void initializeMetricsInstrumentation() {
        if (getMetricsBaseName() == null) {
            setMetricsBaseName(MetricRegistry.name(getClass().getName(), getId()));
        }
        
        final MetricRegistry metricRegistry = MetricsSupport.getMetricRegistry();
        if (metricRegistry != null) {
            timerResolve = metricRegistry.timer(
                    MetricRegistry.name(getMetricsBaseName(), METRIC_TIMER_RESOLVE));
            timerFetchFromOriginSource = metricRegistry.timer(
                    MetricRegistry.name(getMetricsBaseName(), METRIC_TIMER_FETCH_FROM_ORIGIN_SOURCE));

            // Cache for null guarding.
            final com.codahale.metrics.Timer timerResolve2 = timerResolve;
            assert timerResolve2 != null;
            final com.codahale.metrics.Timer timerFetchFromOriginSource2 = timerFetchFromOriginSource;
            assert timerFetchFromOriginSource2 != null;

            // Note that these gauges must use the support method to register in a synchronized fashion,
            // and also must store off the instances for later use in destroy.
            ratioGaugeFetchToResolve = MetricsSupport.register(
                    MetricRegistry.name(getMetricsBaseName(), METRIC_RATIOGAUGE_FETCH_TO_RESOLVE), 
                    new RatioGauge() {
                        protected Ratio getRatio() {
                                return Ratio.of(timerFetchFromOriginSource2.getCount(), 
                                        timerResolve2.getCount());
                        }},
                    true);
            
            gaugeNumLiveEntityIDs = MetricsSupport.register(
                    MetricRegistry.name(getMetricsBaseName(), METRIC_GAUGE_NUM_LIVE_ENTITYIDS),
                    new Gauge<Integer>() {
                        public Integer getValue() {
                            return ensureBackingStore().getIndexedDescriptors().keySet().size();
                        }},
                    true);
            
            gaugePersistentCacheInit = MetricsSupport.register(
                    MetricRegistry.name(getMetricsBaseName(), METRIC_GAUGE_PERSISTENT_CACHE_INIT),
                    new Gauge<PersistentCacheInitializationMetrics>() {
                        public PersistentCacheInitializationMetrics getValue() {
                            return persistentCacheInitMetrics;
                        }},
                    true);
        }
    }
    
    /**
     * Initialize the resolver with data from the persistent cache manager, if enabled.
     */
    protected void initializeFromPersistentCache() {
        if (!isPersistentCachingEnabled()) {
            log.trace("{} Persistent caching is not enabled, skipping init from cache", getLogPrefix());
            return;
        }
        
        log.trace("{} Attempting to load and process entities from the persistent cache", getLogPrefix());
        
        final long start = System.nanoTime();
        try {
            for (final Pair<String, EntityDescriptor> cacheEntry: ensurePersistentCacheManager().listAll()) {
                persistentCacheInitMetrics.entriesTotal++;
                final EntityDescriptor descriptor = cacheEntry.getSecond();
                assert descriptor != null;
                final String currentKey = cacheEntry.getFirst();
                assert currentKey != null;
                final String entityID = StringSupport.trimOrNull(descriptor.getEntityID());
                // This has to be non-null at this point...
                assert entityID != null;
                log.trace("{} Loaded EntityDescriptor from cache store with entityID '{}' and storage key '{}'", 
                        getLogPrefix(), entityID, currentKey);
                
                final EntityManagementData mgmtData = ensureBackingStore().getManagementData(entityID);
                final Lock writeLock = mgmtData.getReadWriteLock().writeLock(); 
                
                try {
                    writeLock.lock();
                    
                    // This can happen if we init from the persistent cache in a background thread,
                    // and metadata for this entityID was resolved before we hit this cache entry.
                    if (!lookupIndexedEntityID(entityID).isEmpty()) {
                        log.trace("{} Metadata for entityID '{}' found in persistent cache was already live, " 
                                + "ignoring cached entry", getLogPrefix(), entityID);
                        persistentCacheInitMetrics.entriesSkippedAlreadyLive++;
                        continue;
                    }
                
                    processPersistentCacheEntry(currentKey, descriptor);
                    
                } finally {
                    writeLock.unlock();
                }
            }
        } catch (final IOException e) {
            log.warn("{} Error loading EntityDescriptors from cache", getLogPrefix(), e);
        } finally {
            persistentCacheInitMetrics.processingTime = System.nanoTime() - start; 
            log.debug("{} Persistent cache initialization metrics: {}", getLogPrefix(), persistentCacheInitMetrics);
        }
    }

    /**
     * Process an entry loaded from the persistent cache.
     * 
     * @param currentKey the current persistent cache key
     * @param descriptor the entity descriptor to process
     */
    protected void processPersistentCacheEntry(@Nonnull final String currentKey, 
            @Nonnull final EntityDescriptor descriptor) {
        
        if (isValid(descriptor)) {
            if (getInitializationFromCachePredicate().test(descriptor)) {
                try {
                    final String entityID = descriptor.getEntityID();
                    assert entityID != null;
                    processNewMetadata(descriptor, entityID, true);
                    log.trace("{} Successfully processed EntityDescriptor with entityID '{}' from cache", 
                            getLogPrefix(), descriptor.getEntityID());
                    persistentCacheInitMetrics.entriesLoaded++;
                } catch (final FilterException | ResolverException e) {
                    log.warn("{} Error processing EntityDescriptor '{}' from cache with storage key '{}'", 
                            getLogPrefix(), descriptor.getEntityID(), currentKey, e);
                    persistentCacheInitMetrics.entriesSkippedProcessingException++;
                }
            } else {
                log.trace("{} Cache initialization predicate indicated to not process EntityDescriptor " 
                        + "with entityID '{}' and cache storage key '{}'",
                        getLogPrefix(), descriptor.getEntityID(), currentKey);
                persistentCacheInitMetrics.entriesSkippedFailedPredicate++;
            }
            
            // Update storage key if necessary, e.g. if cache key generator impl has changed.
            final String expectedKey = getPersistentCacheKeyGenerator().apply(descriptor);
            try {
                if (!Objects.equals(currentKey, expectedKey)) {
                    log.trace("{} Current cache storage key '{}' differs from expected key '{}', updating",
                            getLogPrefix(), currentKey, expectedKey);
                    ensurePersistentCacheManager().updateKey(currentKey, expectedKey);
                    log.trace("{} Successfully updated cache storage key '{}' to '{}'", 
                            getLogPrefix(), currentKey, expectedKey);
                }
            } catch (final IOException e) {
                log.warn("{} Error updating cache storage key '{}' to '{}'", 
                        getLogPrefix(), currentKey, expectedKey, e);
            }
        } else {
                
            log.trace("{} EntityDescriptor with entityID '{}' and storaage key '{}' in cache was " 
                    + "not valid, skipping and removing", getLogPrefix(), descriptor.getEntityID(), currentKey);
            persistentCacheInitMetrics.entriesSkippedInvalid++;
            try {
                ensurePersistentCacheManager().remove(currentKey);
            } catch (final IOException e) {
                log.warn("{} Error removing invalid EntityDescriptor '{}' from persistent cache with key '{}'",
                        getLogPrefix(), descriptor.getEntityID(), currentKey);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void removeByEntityID(@Nonnull final String entityID, @Nonnull final EntityBackingStore backingStore) {
        final List<EntityDescriptor> descriptors = backingStore.getIndexedDescriptors().get(entityID);
        if (descriptors != null) {
            for (final EntityDescriptor descriptor : descriptors) {

                if (indexesEnabled()) {
                    final DynamicEntityBackingStore dynamicStore = (DynamicEntityBackingStore) backingStore;

                    final Lock writeLock = dynamicStore.getSecondaryIndexManager().getReadWriteLock().writeLock();
                    try {
                        writeLock.lock();
                        dynamicStore.getSecondaryIndexManager().deindexEntityDescriptor(descriptor);
                    } finally {
                        writeLock.unlock();
                    }
                }
                
                if (isPersistentCachingEnabled()) {
                    final String key = getPersistentCacheKeyGenerator().apply(descriptor);
                    try {
                        ensurePersistentCacheManager().remove(key);
                    } catch (final IOException e) {
                        log.warn("{} Error removing EntityDescriptor '{}' from cache store with key '{}'", 
                                getLogPrefix(), descriptor.getEntityID(), key);
                    }
                }
                    
            }
        }
        
        super.removeByEntityID(entityID, backingStore);
    }

    /** Tear down when an embedding service refreshes. */
    @OnTeardown
    public void tearDownAbstractDynamicMetadataResolver() {
        if (cleanupTask != null) {
            cleanupTask.cancel();
        }
        if (createdOwnTaskTimer) {
            taskTimer.cancel();
        }
        cleanupTask = null;
        taskTimer = null;
    }

    /** {@inheritDoc}
     * 
     *  This just tears down metrics and will be removed in V6.
     */
    @Override
    protected void doDestroy() {
        
        if (ratioGaugeFetchToResolve != null) {
            MetricsSupport.remove(MetricRegistry.name(getMetricsBaseName(), METRIC_RATIOGAUGE_FETCH_TO_RESOLVE), 
                    ratioGaugeFetchToResolve);
        }
        if (gaugeNumLiveEntityIDs != null) {
            MetricsSupport.remove(MetricRegistry.name(getMetricsBaseName(), METRIC_GAUGE_NUM_LIVE_ENTITYIDS), 
                    gaugeNumLiveEntityIDs);
        }
        if (gaugePersistentCacheInit != null) {
            MetricsSupport.remove(MetricRegistry.name(getMetricsBaseName(), METRIC_GAUGE_PERSISTENT_CACHE_INIT), 
                    gaugePersistentCacheInit);
        }
        
        super.doDestroy();
    }
    
    /** {@inheritDoc} */
    @Override protected void indexEntityDescriptor(@Nonnull final EntityDescriptor entityDescriptor, 
            @Nonnull final EntityBackingStore backingStore) {
        super.indexEntityDescriptor(entityDescriptor, backingStore);
        
        if (indexesEnabled()) {
            final DynamicEntityBackingStore dynamicStore = (DynamicEntityBackingStore) backingStore;

            final Lock writeLock = dynamicStore.getSecondaryIndexManager().getReadWriteLock().writeLock();
            try {
                writeLock.lock();
                dynamicStore.getSecondaryIndexManager().indexEntityDescriptor(entityDescriptor);
            } finally {
                writeLock.unlock();
            }
        }
    }

    /**
     * Specialized entity backing store implementation for dynamic metadata resolvers.
     */
    protected class DynamicEntityBackingStore extends EntityBackingStore {
        
        /** Map holding management data for each entityID. */
        @Nonnull private Map<String, EntityManagementData> mgmtDataMap;
        
        /** Manager for secondary indexes. */
        @Nonnull private LockableMetadataIndexManager<String> secondaryIndexManager;
        
        /** 
         * Constructor.
         * 
         *  @param initIndexes secondary indexes for which to initialize storage
         */
        protected DynamicEntityBackingStore(@Nullable final Set<MetadataIndex> initIndexes) {
            mgmtDataMap = new ConcurrentHashMap<>();
            secondaryIndexManager = new LockableMetadataIndexManager<>(initIndexes, 
                    new LockableMetadataIndexManager.EntityIDExtractionFunction()); 

        }
        
        /**
         * Get the secondary index manager.
         * 
         * @return the manager for secondary indexes
         */
        @Nonnull public LockableMetadataIndexManager<String> getSecondaryIndexManager() {
            return secondaryIndexManager;
        }
        
        /**
         * Get the set of entityIDs which currently have management data.
         *
         * @return set of entityIDs, may be empty
         */
        @Nonnull @Unmodifiable @NotLive public Set<String> getManagementDataEntityIDs() {
            synchronized (this) {
                return CollectionSupport.copyToSet(mgmtDataMap.keySet());
            }
        }

        /**
         * Get the management data for the specified entityID.
         * 
         * @param entityID the input entityID
         * @return the corresponding management data
         */
        @Nonnull public EntityManagementData getManagementData(@Nonnull final String entityID) {
            Constraint.isNotNull(entityID, "EntityID may not be null");
            EntityManagementData entityData = mgmtDataMap.get(entityID);
            if (entityData != null) {
                return entityData;
            }
            
            // TODO use intern-ed String here for monitor target?
            synchronized (this) {
                // Check again in case another thread beat us into the monitor
                entityData = mgmtDataMap.get(entityID);
                if (entityData != null) {
                    return entityData;
                }
                entityData = new EntityManagementData(entityID);
                mgmtDataMap.put(entityID, entityData);
                return entityData;
            }
        }
        
        /**
         * Remove the management data for the specified entityID.
         * 
         * @param entityID the input entityID
         */
        public void removeManagementData(@Nonnull final String entityID) {
            Constraint.isNotNull(entityID, "EntityID may not be null");
            // TODO use intern-ed String here for monitor target?
            synchronized (this) {
                mgmtDataMap.remove(entityID);
            }
        }
        
    }
    
    /**
     * Class holding per-entity management data.
     */
    protected class EntityManagementData {
        
        /** The entity ID managed by this instance. */
        @Nonnull private String entityID;
        
        /** Last update time of the associated metadata. */
        @Nullable private Instant lastUpdateTime;
        
        /** Expiration time of the associated metadata. */
        @Nonnull private Instant expirationTime;
        
        /** Time at which should start attempting to refresh the metadata. */
        @Nonnull private Instant refreshTriggerTime;
        
        /** The last time at which the entity's backing store data was accessed. */
        @Nonnull private Instant lastAccessedTime;
        
        /** The time at which the negative lookup cache flag expires, if set. */
        @Nullable private Instant negativeLookupCacheExpiration;
        
        /** Read-write lock instance which governs access to the entity's backing store data. */
        @Nonnull private ReadWriteLock readWriteLock;
        
        /** Constructor. 
         * 
         * @param id the entity ID managed by this instance
         */
        protected EntityManagementData(@Nonnull final String id) {
            entityID = Constraint.isNotNull(id, "Entity ID was null");
            final Instant now = Instant.now();
            expirationTime = now.plus(getMaxCacheDuration());
            refreshTriggerTime = now.plus(getMaxCacheDuration());
            lastAccessedTime = now;
            readWriteLock = new ReentrantReadWriteLock(true);
        }
        
        /**
         * Get the entity ID managed by this instance.
         * 
         * @return the entity ID
         */
        @Nonnull public String getEntityID() {
            return entityID;
        }
        
        /**
         * Get the last update time of the metadata. 
         * 
         * @return the last update time, or null if no metadata is yet loaded for the entity
         */
        @Nullable public Instant getLastUpdateTime() {
            return lastUpdateTime;
        }

        /**
         * Set the last update time of the metadata.
         * 
         * @param dateTime the last update time
         */
        public void setLastUpdateTime(@Nullable final Instant dateTime) {
            lastUpdateTime = dateTime;
        }
        
        /**
         * Get the expiration time of the metadata. 
         * 
         * @return the expiration time
         */
        @Nonnull public Instant getExpirationTime() {
            return expirationTime;
        }

        /**
         * Set the expiration time of the metadata.
         * 
         * @param dateTime the new expiration time
         */
        public void setExpirationTime(@Nonnull final Instant dateTime) {
            expirationTime = Constraint.isNotNull(dateTime, "Expiration time may not be null");
        }
        
        /**
         * Get the refresh trigger time of the metadata. 
         * 
         * @return the refresh trigger time
         */
        @Nonnull public Instant getRefreshTriggerTime() {
            return refreshTriggerTime;
        }

        /**
         * Set the refresh trigger time of the metadata.
         * 
         * @param dateTime the new refresh trigger time
         */
        public void setRefreshTriggerTime(@Nonnull final Instant dateTime) {
            refreshTriggerTime = Constraint.isNotNull(dateTime, "Refresh trigger time may not be null");
        }

        /**
         * Get the last time at which the entity's backing store data was accessed.
         * 
         * @return last access time
         */
        @Nonnull public Instant getLastAccessedTime() {
            return lastAccessedTime;
        }
        
        /**
         * Record access of the entity's backing store data.
         */
        public void recordEntityAccess() {
            lastAccessedTime = Instant.now();
        }
        
        /**
         * Determine whether the negative lookup cache for the entity is in effect.
         * 
         * @return true if active, false otherwise
         */
        public boolean isNegativeLookupCacheActive() {
            return negativeLookupCacheExpiration != null && Instant.now().isBefore(negativeLookupCacheExpiration);
        }
        
        /**
         * Initialize the negative lookup cache for the entity.
         * 
         * @return the time before which no further lookups for the entity will be performed
         */
        @Nonnull public Instant initNegativeLookupCache() {
            negativeLookupCacheExpiration = Instant.now().plus(getNegativeLookupCacheDuration());
            assert negativeLookupCacheExpiration != null;
            return negativeLookupCacheExpiration;
        }
        
        /**
         * Clear out the negative lookup cache.
         */
        public void clearNegativeLookupCache() {
            negativeLookupCacheExpiration = null;
        }

        /**
         * Get the read-write lock instance which governs access to the entity's backing store data. 
         * 
         * @return the lock instance
         */
        @Nonnull public ReadWriteLock getReadWriteLock() {
            return readWriteLock;
        }
        
    }
    
    /**
     * Background maintenance task which cleans expired and idle metadata from the backing store, and removes
     * orphaned entity management data.
     */
    protected class BackingStoreCleanupSweeper extends TimerTask {
        
        /** Logger. */
        @Nonnull private final Logger log = LoggerFactory.getLogger(BackingStoreCleanupSweeper.class);

        /** {@inheritDoc} */
        @Override
        public void run() {
            if (isDestroyed() || !isInitialized()) {
                // just in case the metadata resolver was destroyed before this task runs, 
                // or if it somehow is being called on a non-successfully-inited resolver instance.
                log.debug("{} BackingStoreCleanupSweeper will not run because: inited: {}, destroyed: {}",
                        getLogPrefix(), isInitialized(), isDestroyed());
                return;
            }
            
            removeExpiredAndIdleMetadata();
        }

        /**
         *  Purge metadata which is either 1) expired or 2) (if {@link #isRemoveIdleEntityData()} is true) 
         *  which hasn't been accessed within the last {@link #getMaxIdleEntityData()} duration.
         */
        private void removeExpiredAndIdleMetadata() {
            final Instant now = Instant.now();
            final Instant earliestValidLastAccessed = now.minus(getMaxIdleEntityData());
            
            final DynamicEntityBackingStore backingStore = ensureBackingStore();
            final Set<String> entityIDs = new HashSet<>();
            entityIDs.addAll(backingStore.getIndexedDescriptors().keySet());
            entityIDs.addAll(backingStore.getManagementDataEntityIDs());
            
            for (final String entityID : entityIDs) {
                assert entityID != null;
                final EntityManagementData mgmtData = backingStore.getManagementData(entityID);
                final Lock writeLock = mgmtData.getReadWriteLock().writeLock();
                try {
                    writeLock.lock();
                    
                    if (isRemoveData(mgmtData, now, earliestValidLastAccessed)) {
                        removeByEntityID(entityID, backingStore);
                        backingStore.removeManagementData(entityID);
                    }
                    
                } finally {
                    writeLock.unlock();
                }
            }
            
        }
        
        /**
         * Determine whether metadata should be removed based on expiration and idle time data.
         * 
         * @param mgmtData the management data instance for the entity
         * @param now the current time
         * @param earliestValidLastAccessed the earliest last accessed time which would be valid
         * 
         * @return true if the entity is expired or exceeds the max idle time, false otherwise
         */
        private boolean isRemoveData(@Nonnull final EntityManagementData mgmtData, 
                @Nonnull final Instant now, @Nonnull final Instant earliestValidLastAccessed) {
            if (isRemoveIdleEntityData() && mgmtData.getLastAccessedTime().isBefore(earliestValidLastAccessed)) {
                log.debug("{} Entity metadata exceeds maximum idle time, removing: {}", 
                        getLogPrefix(), mgmtData.getEntityID());
                return true;
            } else if (now.isAfter(mgmtData.getExpirationTime())) {
                log.debug("{} Entity metadata is expired, removing: {}", getLogPrefix(), mgmtData.getEntityID());
                return true;
            } else {
                return false;
            }
        }
        
    }
    
    /**
     * Default function for generating a cache key for loading and saving an {@link EntityDescriptor}
     * using a {@link XMLObjectLoadSaveManager}.
     */
    public static class DefaultCacheKeyGenerator implements Function<EntityDescriptor, String> {
        
        /** String digester for the EntityDescriptor's entityID. */
        private StringDigester digester;
        
        /** Constructor. */
        public DefaultCacheKeyGenerator() {
            try {
                digester = new StringDigester(JCAConstants.DIGEST_SHA1, OutputFormat.HEX_LOWER);
            } catch (final NoSuchAlgorithmException e) {
                // this can't really happen b/c SHA-1 is required to be supported on all JREs.
            }
        }

        /** {@inheritDoc} */
        @Override
        public String apply(final EntityDescriptor input) {
            if (input == null) {
                return null;
            }
            
            final String entityID = StringSupport.trimOrNull(input.getEntityID());
            if (entityID == null) {
                return null;
            }
            
            return digester.apply(entityID);
        }
        
    }
    
    /**
     * Class used to track metrics related to the initialization from the persistent cache.
     */
    public static class PersistentCacheInitializationMetrics {
        
        /** Whether or not persistent caching was enabled. */
        private boolean enabled;
        
        /** Total processing time for the persistent cache, in nanoseconds. */
        private long processingTime;
        
        /** Total entries seen in the persistent cache. */
        private int entriesTotal;
        
        /** Entries which were successfully loaded and made live. */
        private int entriesLoaded;
        
        /** Entries which were skipped because they were already live by the time they were processed, 
         * generally only seen when initializing from the persistent cache in a background thread. */
        private int entriesSkippedAlreadyLive;
        
        /** Entries which were skipped because they were determined to be invalid. */
        private int entriesSkippedInvalid;
        
        /** Entries which were skipped because they failed the persistent cache predicate evaluation. */
        private int entriesSkippedFailedPredicate;
        
        /** Entries which were skipped due to a processing exception. */
        private int entriesSkippedProcessingException;
        
        /**
         * Get whether or not persistent caching was enabled. 
         * @return Returns the enabled.
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Get total processing time for the persistent cache, in nanoseconds.
         * @return Returns the processingTime.
         */
        public long getProcessingTime() {
            return processingTime;
        }

        /**
         * Get total entries seen in the persistent cache.
         * @return Returns the entriesTotal.
         */
        public int getEntriesTotal() {
            return entriesTotal;
        }

        /**
         * Get entries which were successfully loaded and made live. 
         * @return Returns the entriesLoaded.
         */
        public int getEntriesLoaded() {
            return entriesLoaded;
        }

        /**
         * Get entries which were skipped because they were already live by the time they were processed, 
         * generally only seen when initializing from the persistent cache in a background thread. 
         * @return Returns the entriesSkippedAlreadyLive.
         */
        public int getEntriesSkippedAlreadyLive() {
            return entriesSkippedAlreadyLive;
        }

        /**
         * Get entries which were skipped because they were determined to be invalid.
         * @return Returns the entriesSkippedInvalid.
         */
        public int getEntriesSkippedInvalid() {
            return entriesSkippedInvalid;
        }

        /**
         * Get entries which were skipped because they failed the persistent cache predicate evaluation.
         * @return Returns the entriesSkippedFailedPredicate.
         */
        public int getEntriesSkippedFailedPredicate() {
            return entriesSkippedFailedPredicate;
        }

        /**
         * Get entries which were skipped due to a processing exception. 
         * @return Returns the entriesSkippedProcessingException.
         */
        public int getEntriesSkippedProcessingException() {
            return entriesSkippedProcessingException;
        }

        /** {@inheritDoc} */
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("enabled", enabled)
                    .add("processingTime", processingTime)
                    .add("entriesTotal", entriesTotal)
                    .add("entriesLoaded", entriesLoaded)
                    .add("entriesSkippedAlreadyLive", entriesSkippedAlreadyLive)
                    .add("entriesSkippedInvalid", entriesSkippedInvalid)
                    .add("entriesSkippedFailedPredicate", entriesSkippedFailedPredicate)
                    .add("entriesSkippedProcessingException", entriesSkippedProcessingException)
                    .toString();
        }
        
    }

}
