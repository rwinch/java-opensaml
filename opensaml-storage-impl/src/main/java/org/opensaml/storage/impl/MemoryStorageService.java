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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TimerTask;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.annotation.constraint.Live;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.LoggerFactory;

import org.opensaml.storage.AbstractMapBackedStorageService;
import org.opensaml.storage.MutableStorageRecord;
import org.opensaml.storage.StorageCapabilities;
import org.slf4j.Logger;

/**
 * Implementation of {@link AbstractMapBackedStorageService} that stores data in-memory in a shared data structure 
 * with no persistence.
 */
public class MemoryStorageService extends AbstractMapBackedStorageService implements StorageCapabilities {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(MemoryStorageService.class);

    /** Map of contexts. */
    @NonnullAfterInit private Map<String, Map<String, MutableStorageRecord<?>>> contextMap;
    
    /** A shared lock to synchronize access. */
    @NonnullAfterInit private ReadWriteLock lock;

    /** {@inheritDoc} */
    public boolean isServerSide() {
        return true;
    }

    /** {@inheritDoc} */
    public boolean isClustered() {
        return false;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        contextMap = new HashMap<>();
        lock = new ReentrantReadWriteLock(true);
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull @Live protected Map<String, Map<String, MutableStorageRecord<?>>> getContextMap() {
        checkComponentActive();
        assert contextMap != null;
        return contextMap;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected ReadWriteLock getLock() {
        checkComponentActive();
        assert lock != null;
        return lock;
    }
    
// Checkstyle: AnonInnerLength OFF
    /** {@inheritDoc} */
    @Override
    @Nullable protected TimerTask getCleanupTask() {
        return new TimerTask() {
            
            /** {@inheritDoc} */
            @Override
            public void run() {
                log.debug("Running cleanup task");
                
                final Long now = System.currentTimeMillis();
                final Lock writeLock = getLock().writeLock();
                boolean purged = false;
                
                try {
                    writeLock.lock();
                    
                    final Collection<Map<String, MutableStorageRecord<?>>> contexts = getContextMap().values();
                    final Iterator<Map<String, MutableStorageRecord<?>>> i = contexts.iterator();
                    while (i.hasNext()) {
                        final Map<String, MutableStorageRecord<?>> context = i.next();
                        assert context != null;
                        if (reapWithLock(context, now)) {
                            purged = true;
                            if (context.isEmpty()) {
                                i.remove();
                            }
                        }
                    }
                    
                } finally {
                    writeLock.unlock();
                }
                
                if (purged) {
                    log.debug("Purged expired record(s) from storage");
                } else {
                    log.debug("No expired records found in storage");
                }
            }
        };
    }
// Checkstyle: AnonInnerLength ON

}