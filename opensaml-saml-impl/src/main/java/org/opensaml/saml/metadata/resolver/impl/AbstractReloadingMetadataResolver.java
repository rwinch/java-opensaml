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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Timer;
import java.util.TimerTask;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.metrics.MetricsSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.metadata.resolver.RefreshableMetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.saml2.common.SAML2Support;
import org.opensaml.saml.saml2.common.TimeBoundSAMLObject;
import org.slf4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer.Context;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.TimerSupport;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * Base class for metadata providers that cache and periodically refresh their metadata.
 * 
 * This metadata provider periodically checks to see if the read metadata file has changed. The delay between each
 * refresh interval is calculated as follows. If no validUntil or cacheDuration is present then the
 * {@link #getMaxRefreshDelay()} value is used. Otherwise, the earliest refresh interval of the metadata file is checked
 * by looking for the earliest of all the validUntil attributes and cacheDuration attributes. If that refresh interval
 * is larger than the max refresh delay then {@link #getMaxRefreshDelay()} is used. If that number is smaller than the
 * min refresh delay then {@link #getMinRefreshDelay()} is used. Otherwise the calculated refresh delay multiplied by
 * {@link #getRefreshDelayFactor()} is used. By using this factor, the provider will attempt to be refresh before the
 * cache actually expires, allowing a some room for error and recovery. Assuming the factor is not exceedingly close to
 * 1.0 and a min refresh delay that is not overly large, this refresh will likely occur a few times before the cache
 * expires.
 */
public abstract class AbstractReloadingMetadataResolver extends AbstractBatchMetadataResolver 
        implements RefreshableMetadataResolver {

    /** Metric name for the timer for {@link #refresh()}. */
    @Nonnull @NotEmpty public static final String METRIC_TIMER_REFRESH = "timer.refresh";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractReloadingMetadataResolver.class);

    /** Timer used to schedule background metadata update tasks. */
    @Nonnull private Timer taskTimer;
    
    /** Whether we created our own task timer during object construction. */
    private boolean createdOwnTaskTimer;
        
    /** Current task to refresh metadata. */
    @Nullable private RefreshMetadataTask refreshMetadataTask;
    
    /** Factor used to compute when the next refresh interval will occur. Default value: 0.75 */
    private float refreshDelayFactor = 0.75f;

    /**
     * Refresh interval used when metadata does not contain any validUntil or cacheDuration information.
     * Default value: 4 hours.
     */
    @Nonnull private Duration maxRefreshDelay;

    /** Floor for the refresh interval. Default value: 5 minutes. */
    @Nonnull private Duration minRefreshDelay;

    /** Time when the currently cached metadata file expires. */
    @Nullable private Instant expirationTime;
    
    /** Impending expiration warning threshold for metadata refresh. Default value: 0 (disabled). */
    @Nonnull private Duration expirationWarningThreshold;

    /** Last time the metadata was updated. */
    @Nullable private Instant lastUpdate;

    /** Last time a refresh cycle occurred. */
    @Nullable private Instant lastRefresh;

    /** Next time a refresh cycle will occur. */
    @Nullable private Instant nextRefresh;
    
    /** Last time a successful refresh cycle occurred. */
    @Nullable private Instant lastSuccessfulRefresh;

    /** Flag indicating whether last refresh cycle was successful. */
    @Nullable private Boolean wasLastRefreshSuccess;
    
    /** Internal flag for tracking success during the refresh operation. */
    private boolean trackRefreshSuccess;
    
    /** Reason for the failure of the last refresh.  Will be null if last refresh was success. */
    @Nullable private Throwable lastFailureCause;

    /** Metrics Timer for {@link #refresh()}. */
    @Nullable private com.codahale.metrics.Timer timerRefresh;

    /** Constructor. */
    protected AbstractReloadingMetadataResolver() {
        this(null);
    }

    /**
     * Constructor.
     * 
     * @param backgroundTaskTimer time used to schedule background refresh tasks
     */
    protected AbstractReloadingMetadataResolver(@Nullable final Timer backgroundTaskTimer) {
        setCacheSourceMetadata(true);
        
        minRefreshDelay = Duration.ofMinutes(5);
        maxRefreshDelay = Duration.ofHours(4);
        
        expirationWarningThreshold = Duration.ZERO;
        
        if (backgroundTaskTimer == null) {
            taskTimer = new Timer(TimerSupport.getTimerName(this), true);
            createdOwnTaskTimer = true;
        } else {
            taskTimer = backgroundTaskTimer;
        }
    }
    
    /** {@inheritDoc} */
    @Override
    protected void setCacheSourceMetadata(final boolean flag) {
        checkSetterPreconditions();

        if (!flag) {
            log.warn("{} Caching of source metadata may not be disabled for reloading metadata resolvers", 
                    getLogPrefix());
        } else {
            super.setCacheSourceMetadata(flag);
        }
    }

    /**
     * Gets the time when the currently cached metadata expires.
     * 
     * @return time when the currently cached metadata expires, or null if no metadata is cached
     */
    @Nullable public Instant getExpirationTime() {
        return expirationTime;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public Instant getLastUpdate() {
        return lastUpdate;
    }

    /** {@inheritDoc} */
    @Override @Nullable public Instant getLastRefresh() {
        return lastRefresh;
    }
    
    /** {@inheritDoc} */
    @Nullable public Instant getLastSuccessfulRefresh() {
        return lastSuccessfulRefresh;
    }

    /** {@inheritDoc} */
    @Nullable public Boolean wasLastRefreshSuccess() {
        return wasLastRefreshSuccess;
    }

    /** {@inheritDoc} */
    @Nullable public Throwable getLastFailureCause() {
        return lastFailureCause;
    }

    /**
     * Gets the time when the next refresh cycle will occur.
     * 
     * @return time when the next refresh cycle will occur
     */
    @Nullable public Instant getNextRefresh() {
        return nextRefresh;
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
    public void setExpirationWarningThreshold(@Nonnull final Duration threshold) {
        checkSetterPreconditions();

        Constraint.isNotNull(threshold, "Expiration warning threshold cannot be null");
        Constraint.isFalse(threshold.isNegative(), "Expiration warning threshold cannot be negative");
        
        expirationWarningThreshold = threshold;
    }
    
    /**
     * Gets the maximum amount of time between refresh intervals.
     * 
     * @return maximum amount of time between refresh intervals
     */
    @Nonnull public Duration getMaxRefreshDelay() {
        return maxRefreshDelay;
    }

    /**
     * Sets the maximum amount of time between refresh intervals.
     * 
     * @param delay maximum amount of time between refresh intervals
     */
    public void setMaxRefreshDelay(@Nonnull final Duration delay) {
        checkSetterPreconditions();

        Constraint.isNotNull(delay, "Maximum refresh delay cannot be null");
        Constraint.isFalse(delay.isNegative() || delay.isZero(), "Maximum refresh delay must be greater than 0");

        maxRefreshDelay = delay;
    }

    /**
     * Gets the delay factor used to compute the next refresh time.
     * 
     * @return delay factor used to compute the next refresh time
     */
    public float getRefreshDelayFactor() {
        return refreshDelayFactor;
    }

    /**
     * Sets the delay factor used to compute the next refresh time. The delay must be between 0.0 and 1.0, exclusive.
     * 
     * @param factor delay factor used to compute the next refresh time
     */
    public void setRefreshDelayFactor(final float factor) {
        checkSetterPreconditions();

        if (factor <= 0 || factor >= 1) {
            throw new IllegalArgumentException("Refresh delay factor must be a number between 0.0 and 1.0, exclusive");
        }

        refreshDelayFactor = factor;
    }

    /**
     * Gets the minimum amount of time between refreshes.
     * 
     * @return minimum amount of time between refreshes
     */
    @Nonnull public Duration getMinRefreshDelay() {
        return minRefreshDelay;
    }

    /**
     * Sets the minimum amount of time between refreshes.
     * 
     * @param delay minimum amount of time between refreshes
     */
    public void setMinRefreshDelay(@Nonnull final Duration delay) {
        checkSetterPreconditions();

        Constraint.isNotNull(delay, "Minimum refresh delay cannot be null");
        Constraint.isFalse(delay.isNegative() || delay.isZero(), "Minimum refresh delay must be greater than 0");

        minRefreshDelay = delay;
    }

    /** {@inheritDoc} */
    @Override
    protected void doDestroy() {
        if (refreshMetadataTask != null) {
            refreshMetadataTask.cancel();
        }
        
        if (createdOwnTaskTimer) {
            taskTimer.cancel();
        }
        
        super.doDestroy();
    }

    /** {@inheritDoc} */
    @Override
    protected void initMetadataResolver() throws ComponentInitializationException {
        super.initMetadataResolver();
        
        if (getMetricsBaseName() == null) {
            setMetricsBaseName(MetricRegistry.name(getClass().getName(), getId()));
        }

        final MetricRegistry metricRegistry = MetricsSupport.getMetricRegistry();
        if (metricRegistry != null) {
            timerRefresh = metricRegistry.timer(
                    MetricRegistry.name(getMetricsBaseName(), METRIC_TIMER_REFRESH));
        }
        
        try {
            refresh();
        } catch (final ResolverException e) {
            throw new ComponentInitializationException("Error refreshing metadata during init", e);
        }
        
        if (minRefreshDelay.compareTo(maxRefreshDelay) > 0) {
            throw new ComponentInitializationException("Minimum refresh delay " + minRefreshDelay
                    + " is greater than maximum refresh delay " + maxRefreshDelay);
        }
    }

// Checkstyle: MethodLength OFF
    /**
     * Refreshes the metadata from its source.
     * 
     * @throws ResolverException thrown is there is a problem retrieving and processing the metadata
     */
    @Override
    public synchronized void refresh() throws ResolverException {
        Instant now = null;
        String mdId = null;
        trackRefreshSuccess = false;

        Context contextRefresh = null;
        try {

            // In case a destroy() thread beat this thread into the monitor.
            if (isDestroyed()) {
                return;
            }

            // A manual refresh() must cancel the previously-scheduled future task, since will (re)schedule its own.
            // If this execution *is* the task, it's ok to cancel ourself, we're already running.
            if (refreshMetadataTask != null) {
                refreshMetadataTask.cancel();
            }
            
            now = Instant.now();
            mdId = getMetadataIdentifier();

            log.debug("{} Beginning refresh of metadata from '{}'", getLogPrefix(), mdId);
        
            final byte[] mdBytes = fetchMetadata();
            if (mdBytes == null) {
                log.info("{} Metadata from '{}' has not changed since last refresh", getLogPrefix(), mdId);
                processCachedMetadata(mdId, now);
            } else {
                log.debug("{} Processing new metadata from '{}'", getLogPrefix(), mdId);
                // Start timer for refresh.
                contextRefresh = MetricsSupport.startTimer(timerRefresh);
                processNewMetadata(mdId, now, mdBytes);
            }
        } catch (final Throwable t) {
            trackRefreshSuccess = false;
            lastFailureCause = t;
            nextRefresh = Instant.now().plus(computeNextRefreshDelay(null));
            log.error("{} Error occurred while attempting to refresh metadata from '{}'", getLogPrefix(), mdId, t);
            if (t instanceof Exception) {
                throw new ResolverException("Exception during refresh", (Exception) t);
            }
            throw new ResolverException(String.format("Saw an error of type '%s' with message '%s'", 
                    t.getClass().getName(), t.getMessage()));
        } finally {
            // Close out timer if started.
            if (contextRefresh != null) {
                MetricsSupport.stopTimer(contextRefresh);
            }
            
            if (now != null) {
                logCachedMetadataExpiration(now);
            }
            
            if (trackRefreshSuccess) {
                wasLastRefreshSuccess = true;
                lastSuccessfulRefresh = now;
                lastFailureCause = null;
            } else {
                wasLastRefreshSuccess = false;
            }
            
            refreshMetadataTask = new RefreshMetadataTask();
            final Instant nextRefreshCopy = nextRefresh;
            // TODO: why is this actually non-null here? Needs review.
            assert nextRefreshCopy != null;
            final long nextRefreshDelay = nextRefreshCopy.toEpochMilli() - System.currentTimeMillis();
            taskTimer.schedule(refreshMetadataTask, nextRefreshDelay);
            log.info("{} Next refresh cycle for metadata provider '{}' will occur on '{}' ('{}' local time)",
                    new Object[] {getLogPrefix(), mdId, nextRefresh, nextRefreshCopy.atZone(ZoneId.systemDefault()),});
            lastRefresh = now;
        }
    }
// Checkstyle: MethodLength ON

    /**
     * Check cached metadata for expiration or pending expiration and log appropriately.
     *
     * @param now the current date/time
     */
    private void logCachedMetadataExpiration(@Nonnull final Instant now) {
        final String mdId = getMetadataIdentifier();
        final XMLObject cached = ensureBackingStore().getCachedOriginalMetadata();
        if (cached != null && !isValid(cached)) {
            log.warn("{} Metadata root from '{}' currently live (post-refresh) is expired or otherwise invalid",
                    getLogPrefix(), mdId);
        } else if (cached instanceof TimeBoundSAMLObject timebound) {
            if (isRequireValidMetadata()) {
                final Instant validUntil = timebound.getValidUntil();
                if (validUntil != null) {
                    if (!getExpirationWarningThreshold().isZero() 
                            && validUntil.isBefore(now.plus(getExpirationWarningThreshold()))) {
                        log.warn("{} Metadata root from '{}' currently live (post-refresh) will expire "
                                + "within the configured threshhold at '{}'",
                                getLogPrefix(), mdId, timebound.getValidUntil());
                    } else if (validUntil.isBefore(nextRefresh)) {
                        log.warn("{} Metadata root from '{}' currently live (post-refresh) will expire "
                                + "at '{}' before the next refresh scheduled for {}'",
                                getLogPrefix(), mdId, timebound.getValidUntil(), nextRefresh);
                    }
                }
            }
        }
    }

    /**
     * Gets an identifier which may be used to distinguish this metadata in logging statements.
     * 
     * @return identifier which may be used to distinguish this metadata in logging statements
     */
    protected abstract String getMetadataIdentifier();

    /**
     * Fetches metadata from a source.
     * 
     * @return the fetched metadata, or null if the metadata is known not to have changed since the last retrieval
     * 
     * @throws ResolverException thrown if there is a problem fetching the metadata
     */
    protected abstract byte[] fetchMetadata() throws ResolverException;

    /**
     * Unmarshalls the given metadata bytes.
     * 
     * @param metadataBytes raw metadata bytes
     * 
     * @return the metadata
     * 
     * @throws ResolverException thrown if the metadata can not be unmarshalled
     */
    @Nonnull protected XMLObject unmarshallMetadata(@Nonnull final byte[] metadataBytes) throws ResolverException {
        try {
            return unmarshallMetadata(new ByteArrayInputStream(metadataBytes));
        } catch (final UnmarshallingException e) {
            final String errorMsg = "Unable to unmarshall metadata";
            log.error("{} {}: {}", getLogPrefix(), errorMsg, e.getMessage());
            throw new ResolverException(errorMsg, e);
        }
    }

    /**
     * Processes a cached metadata document in order to determine, and schedule, the next time it should be refreshed.
     * 
     * @param metadataIdentifier identifier of the metadata source
     * @param refreshStart when the current refresh cycle started
     * 
     * @throws ResolverException throw is there is a problem process the cached metadata
     */
    protected void processCachedMetadata(@Nonnull final String metadataIdentifier, @Nonnull final Instant refreshStart)
            throws ResolverException {
        log.debug("{} Computing new expiration time for cached metadata from '{}'", getLogPrefix(), metadataIdentifier);
        final Instant metadataExpirationTime = 
                SAML2Support.getEarliestExpiration(ensureBackingStore().getCachedOriginalMetadata(),
                refreshStart.plus(getMaxRefreshDelay()), refreshStart);

        trackRefreshSuccess = true;
        expirationTime = metadataExpirationTime;
        nextRefresh = Instant.now().plus(computeNextRefreshDelay(expirationTime));
    }

    /**
     * Process a new metadata document. Processing include unmarshalling and filtering metadata, determining the next
     * time is should be refreshed and scheduling the next refresh cycle.
     * 
     * @param metadataIdentifier identifier of the metadata source
     * @param refreshStart when the current refresh cycle started
     * @param metadataBytes raw bytes of the new metadata document
     * 
     * @throws ResolverException thrown if there is a problem unmarshalling or filtering the new metadata
     */
    protected void processNewMetadata(@Nonnull final String metadataIdentifier, @Nonnull final Instant refreshStart,
            @Nonnull final byte[] metadataBytes) throws ResolverException {
        log.debug("{} Unmarshalling metadata from '{}'", getLogPrefix(), metadataIdentifier);
        final XMLObject metadata = unmarshallMetadata(metadataBytes);

        if (!isValid(metadata)) {
            processPreExpiredMetadata(metadataIdentifier, refreshStart, metadataBytes, metadata);
        } else {
            processNonExpiredMetadata(metadataIdentifier, refreshStart, metadataBytes, metadata);
        }
    }

    /**
     * Processes metadata that has been determined to be invalid (usually because it's already expired) at the time it
     * was fetched. A metadata document is considered be invalid if its root element returns false when passed to the
     * {@link #isValid(XMLObject)} method.
     * 
     * @param metadataIdentifier identifier of the metadata source
     * @param refreshStart when the current refresh cycle started
     * @param metadataBytes raw bytes of the new metadata document
     * @param metadata new metadata document unmarshalled
     */
    protected void processPreExpiredMetadata(@Nonnull final String metadataIdentifier,
            @Nonnull final Instant refreshStart, @Nonnull final byte[] metadataBytes,
            @Nonnull final XMLObject metadata) {
        log.warn("{} Entire metadata document from '{}' was expired at time of loading, " 
                + "previous metadata retained, if any", getLogPrefix(), metadataIdentifier);

        nextRefresh = Instant.now().plus(computeNextRefreshDelay(null));
        trackRefreshSuccess = false;
        // Note: We don't throw this b/c it would change behavior wrt to init and failFast,
        // but we still want to expose the failure cause to clients.
        lastFailureCause = new ResolverException("Entire metadata document was already expired at time of loading");
    }

    /**
     * Processes metadata that has been determined to be valid at the time it was fetched. A metadata document is
     * considered to be valid if its root element returns true when passed to the {@link #isValid(XMLObject)} method.
     * 
     * @param metadataIdentifier identifier of the metadata source
     * @param refreshStart when the current refresh cycle started
     * @param metadataBytes raw bytes of the new metadata document
     * @param metadata new metadata document unmarshalled
     * 
     * @throws ResolverException thrown if there s a problem processing the metadata
     */
    protected void processNonExpiredMetadata(@Nonnull final String metadataIdentifier,
            @Nonnull final Instant refreshStart, @Nonnull final byte[] metadataBytes,
            @Nonnull final XMLObject metadata) throws ResolverException {
        final Element domElement = metadata.getDOM();
        assert domElement != null;
        final Document metadataDom = domElement.getOwnerDocument();

        log.debug("{} Preprocessing metadata from '{}'", getLogPrefix(), metadataIdentifier);
        BatchEntityBackingStore newBackingStore = null;
        try {
            newBackingStore = preProcessNewMetadata(metadata);
        } catch (final FilterException e) {
            final String errMsg = "Error filtering metadata from " + metadataIdentifier;
            log.error("{} {}: {}", getLogPrefix(), errMsg, e.getMessage());
            throw new ResolverException(errMsg, e);
        }

        log.debug("{} Releasing cached DOM for metadata from '{}'", getLogPrefix(), metadataIdentifier);
        releaseMetadataDOM(newBackingStore.getCachedOriginalMetadata());
        releaseMetadataDOM(newBackingStore.getCachedFilteredMetadata());

        log.debug("{} Post-processing metadata from '{}'", getLogPrefix(), metadataIdentifier);
        postProcessMetadata(metadataBytes, metadataDom, newBackingStore.ensureCachedOriginalMetadata(), 
                newBackingStore.getCachedFilteredMetadata());

        log.debug("{} Computing expiration time for metadata from '{}'", getLogPrefix(), metadataIdentifier);
        // Note: As noted in its Javadocs, technically this method can sometimes return null, but won't in this case
        // since the candidate time (2nd arg) is not null.
        final Instant metadataExpirationTime = SAML2Support.getEarliestExpiration(
                newBackingStore.getCachedOriginalMetadata(), refreshStart.plus(getMaxRefreshDelay()), refreshStart);
        assert metadataExpirationTime != null;
        log.debug("{} Expiration of metadata from '{}' will occur at {}", getLogPrefix(), metadataIdentifier, 
                metadataExpirationTime);

        // This is where the new processed data becomes effective. Exceptions thrown prior to this point
        // therefore result in the old data being kept effective.
        setBackingStore(newBackingStore);
        
        lastUpdate = refreshStart;
        trackRefreshSuccess = true;
        
        final Instant now = Instant.now();
        
        final Duration nextRefreshDelay;
        if (metadataExpirationTime.isBefore(now)) {
            expirationTime = now.plus(getMinRefreshDelay());
            nextRefreshDelay = getMaxRefreshDelay();
        } else {
            expirationTime = metadataExpirationTime;
            nextRefreshDelay = computeNextRefreshDelay(expirationTime);
        }
        nextRefresh = now.plus(nextRefreshDelay);

        log.info("{} New metadata successfully loaded for '{}'", getLogPrefix(), getMetadataIdentifier());
    }

    /**
     * Post-processing hook called after new metadata has been unmarshalled, filtered, and the DOM released (from the
     * {@link XMLObject}) but before the metadata is saved off. Any exception thrown by this hook will cause the
     * retrieved metadata to be discarded.
     * 
     * The default implementation of this method is a no-op
     * 
     * @param metadataBytes original raw metadata bytes retrieved via {@link #fetchMetadata}
     * @param metadataDom original metadata after it has been parsed in to a DOM document
     * @param originalMetadata original metadata prior to being filtered, with its DOM released
     * @param filteredMetadata metadata after it has been run through all registered filters and its DOM released
     * 
     * @throws ResolverException thrown if there is a problem with the provided data
     */
    protected void postProcessMetadata(@Nonnull final byte[] metadataBytes, @Nonnull final Document metadataDom,
            @Nonnull final XMLObject originalMetadata, @Nullable final XMLObject filteredMetadata)
                    throws ResolverException {
    }

    /**
     * Computes the delay until the next refresh time based on the current metadata's expiration time and the refresh
     * interval floor.
     * 
     * @param expectedExpiration the time when the metadata is expected to expire and need refreshing
     * 
     * @return delay until the next refresh time
     */
    @Nonnull protected Duration computeNextRefreshDelay(@Nullable final Instant expectedExpiration) {
        final long now = System.currentTimeMillis();

        long expireInstant = 0;
        if (expectedExpiration != null) {
            expireInstant = expectedExpiration.toEpochMilli();
        }
        long refreshDelay = (long) ((expireInstant - now) * getRefreshDelayFactor());

        // if the expiration time was null or the calculated refresh delay was less than the floor
        // use the floor
        if (refreshDelay < getMinRefreshDelay().toMillis()) {
            refreshDelay = getMinRefreshDelay().toMillis();
        }

        return Duration.ofMillis(refreshDelay);
    }

    /**
     * Converts an InputStream into a byte array.
     * 
     * @param ins input stream to convert. The stream will be closed after its data is consumed.
     * 
     * @return resultant byte array
     * 
     * @throws ResolverException thrown if there is a problem reading the resultant byte array
     */
    @Nonnull protected byte[] inputstreamToByteArray(@Nonnull final InputStream ins) throws ResolverException {
        try (ins) {
            // 1 MB read buffer
            final byte[] buffer = new byte[1024 * 1024];
            final ByteArrayOutputStream output = new ByteArrayOutputStream();

            int n = 0;
            while (-1 != (n = ins.read(buffer))) {
                output.write(buffer, 0, n);
            }

            return output.toByteArray();
        } catch (final IOException e) {
            throw new ResolverException(e);
        }
    }

    /** Background task that refreshes metadata. */
    private class RefreshMetadataTask extends TimerTask {

        /** {@inheritDoc} */
        //CheckStyle: ReturnCount OFF
        @Override public void run() {
            try {
                if (isDestroyed()) {
                    // just in case the metadata provider was destroyed before this task runs
                    return;
                }
                
                refresh();
            } catch (final ResolverException e) {
                // nothing to do, error message already logged by refreshMetadata()
                return;
            }
        }
        //CheckStyle: ReturnCount ON
    }

}