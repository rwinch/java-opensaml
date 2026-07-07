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

package org.opensaml.saml.common.binding.artifact.impl;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.artifact.ExpiringSAMLArtifactMapEntry;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.OnTeardown;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.TimerSupport;

/** Basic artifact map implementation. */
public class BasicSAMLArtifactMap extends AbstractInitializableComponent implements
        SAMLArtifactMap {

    /** Class Logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BasicSAMLArtifactMap.class);

    /** Artifact mapping storage. */
    @NonnullAfterInit private Map<String,ExpiringSAMLArtifactMapEntry> artifactStore;

    /** Lifetime of an artifact. */
    @Nonnull private Duration artifactLifetime;

    /** Factory for SAMLArtifactMapEntry instances. */
    @Nonnull private SAMLArtifactMapEntryFactory entryFactory;

    /** Time between cleanup checks. Default value: (5 mins) */
    @Nonnull private Duration cleanupInterval;

    /** Timer used to schedule cleanup tasks. */
    @NonnullAfterInit private Timer cleanupTaskTimer;

    /** Task that cleans up expired records. */
    @Nullable private TimerTask cleanupTask;

    /** Constructor. */
    public BasicSAMLArtifactMap() {
        artifactLifetime = Duration.ofMinutes(1);
        cleanupInterval = Duration.ofMinutes(5);
        entryFactory = new ExpiringSAMLArtifactMapEntryFactory();
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        artifactStore = new ConcurrentHashMap<>();

        if (!cleanupInterval.isZero()) {
            cleanupTask = new Cleanup();
            cleanupTaskTimer = new Timer(TimerSupport.getTimerName(this), true);
            cleanupTaskTimer.schedule(cleanupTask, cleanupInterval.toMillis(), cleanupInterval.toMillis());
        }
    }

    /**
     * Tear down worker tasks when the containing service reloads.
     */
    @OnTeardown
    public final synchronized void teardownBasicSAMLArtifactMap() {
        if (cleanupTask != null) {
            cleanupTask.cancel();
            cleanupTask = null;
            cleanupTaskTimer = null;
        }
        artifactStore = null;
    }

    /**
     * Get the artifact entry lifetime.
     * 
     * @return the artifact entry lifetime
     */
    @Nonnull public Duration getArtifactLifetime() {
        return artifactLifetime;
    }

    /**
     * Get the map entry factory.
     * 
     * @return the map entry factory
     */
    @Nonnull public SAMLArtifactMapEntryFactory getEntryFactory() {
        return entryFactory;
    }

    /**
     * Set the artifact entry lifetime.
     * 
     * @param lifetime artifact entry lifetime
     */
    public void setArtifactLifetime(@Nonnull final Duration lifetime) {
        checkSetterPreconditions();
        Constraint.isNotNull(lifetime, "Lifetime cannot be null");
        Constraint.isFalse(lifetime.isNegative() || lifetime.isZero(), "Lifetime must be positive");
        
        artifactLifetime = lifetime;
    }

    /**
     * Set the cleanup interval, or 0 for none.
     * 
     * @param interval  cleanup interval
     */
    public void setCleanupInterval(@Nonnull final Duration interval) {
        checkSetterPreconditions();
        Constraint.isNotNull(interval, "Interval cannot be null");
        Constraint.isFalse(interval.isNegative(), "Interval cannot be negative");

        cleanupInterval = interval;
    }
    
    /**
     * Set the map entry factory.
     * 
     * @param factory map entry factory
     */
    public void setEntryFactory(@Nonnull final SAMLArtifactMapEntryFactory factory) {
        checkSetterPreconditions();
        
        entryFactory = Constraint.isNotNull(factory, "SAMLArtifactMapEntryFactory cannot be null");
    }

    /** {@inheritDoc} */
    public boolean contains(@Nonnull @NotEmpty final String artifact) throws IOException {
        return artifactStore.containsKey(artifact);
    }

    /** {@inheritDoc} */
    @Nullable public SAMLArtifactMapEntry get(@Nonnull @NotEmpty final String artifact) throws IOException {
        log.debug("Attempting to retrieve entry for artifact: {}", artifact);
        final ExpiringSAMLArtifactMapEntry entry = artifactStore.get(artifact);

        if (entry == null) {
            log.debug("No entry found for artifact: {}", artifact);
            return null;
        }

        if (!entry.isValid()) {
            log.debug("Entry for artifact was expired: {}", artifact);
            remove(artifact);
            return null;
        }

        log.debug("Found valid entry for artifact: {}", artifact);
        return entry;
    }

    /** {@inheritDoc} */
    public void put(@Nonnull @NotEmpty final String artifact, @Nonnull @NotEmpty final String relyingPartyId,
            @Nonnull @NotEmpty final String issuerId, @Nonnull final SAMLObject samlMessage) throws IOException {

        final ExpiringSAMLArtifactMapEntry artifactEntry =
                (ExpiringSAMLArtifactMapEntry) entryFactory.newEntry(artifact, issuerId, relyingPartyId, samlMessage);
        artifactEntry.setExpiration(Instant.now().plus(getArtifactLifetime()));

        if (log.isDebugEnabled()) {
            log.debug("Storing new artifact entry '{}' for relying party '{}', expiring at '{}'", new Object[] {
                    artifact, relyingPartyId, artifactEntry.getExpiration(),});
        }

        artifactStore.put(artifact, artifactEntry);
    }

    /** {@inheritDoc} */
    public void remove(@Nonnull @NotEmpty final String artifact) throws IOException {
        log.debug("Removing artifact entry: {}", artifact);

        artifactStore.remove(artifact);
    }

    /**
     * A cleanup task that relies on the weakly consistent iterator support in the map implementation.
     */
    protected class Cleanup extends TimerTask {

        /** {@inheritDoc} */
        @Override public void run() {
            log.info("Running cleanup task");

            final Instant now = Instant.now();

            final Iterator<Map.Entry<String, ExpiringSAMLArtifactMapEntry>> i = artifactStore.entrySet().iterator();
            while (i.hasNext()) {
                final Map.Entry<String, ExpiringSAMLArtifactMapEntry> entry = i.next();
                if (!entry.getValue().isValid(now)) {
                    i.remove();
                }
            }
        }
    }

}