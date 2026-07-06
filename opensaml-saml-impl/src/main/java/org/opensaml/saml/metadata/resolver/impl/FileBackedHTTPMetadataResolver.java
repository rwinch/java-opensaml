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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.hc.client5.http.classic.HttpClient;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilterContext;
import org.opensaml.saml.metadata.resolver.filter.data.impl.MetadataSource;
import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.google.common.io.Files;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * An HTTP metadata provider that caches a copy of the retrieved metadata to disk so that, in the event that
 * the metadata may not be pulled from the URL, it may be pulled from disk using the most recently fetched data.
 * 
 * <p>
 * If the backup file does not already exist, it will be created by saving the byte[] retrieved in the HTTP fetch.
 * </p>
 * 
 * <p>
 * If {@link #isInitializeFromBackupFile()} is true, then initialization will attempt to load metadata first
 * from the backup file on disk, if it exists.  If successful then the next refresh after initialization, which 
 * will attempt the full HTTP fetch, will be scheduled for the interval indicated by 
 * {@link #getBackupFileInitNextRefreshDelay()}. This can help prevent large metadata batches from slowing down
 * the synchronous resolver start up process, deferring the more expensive HTTP fetch operation to the asynchronous
 * background refresh thread.
 * </p>
 * 
 */
public class FileBackedHTTPMetadataResolver extends HTTPMetadataResolver {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(FileBackedHTTPMetadataResolver.class);

    /** File containing the backup of the metadata. */
    @Nonnull private File metadataBackupFile;
    
    /** Flag used to track state of whether currently initializing or not. */
    private boolean initializing;
    
    /** Flag indicating whether initialization should first attempt to load metadata from backup file. */
    private boolean initializeFromBackupFile = true;
    
    /** Flag indicating whether metadata load during init was from backup file. */
    private boolean initializedFromBackupFile;
    
    /** Duration after which to schedule next refresh, when initialized from backup file. */
    @Nonnull private Duration backupFileInitNextRefreshDelay;
    
    /**
     * Constructor.
     * 
     * @param client HTTP client used to fetch remote metadata
     * @param metadataURL the URL to fetch the metadata
     * @param backupFilePath the file that will keep a backup copy of the metadata,
     * 
     * @throws ResolverException thrown if the URL is not a valid URL, the metadata can not be retrieved from
     *             the URL
     */
    public FileBackedHTTPMetadataResolver(@Nonnull final HttpClient client, @Nonnull final String metadataURL,
            @Nonnull final String backupFilePath) throws ResolverException {
        this(null, client, metadataURL, backupFilePath);
    }

    /**
     * Constructor.
     * 
     * @param client HTTP client used to fetch remote metadata
     * @param backgroundTaskTimer timer used to schedule background metadata refresh tasks
     * @param metadataURL the URL to fetch the metadata
     * @param backupFilePath the file that will keep a backup copy of the metadata,
     * 
     * @throws ResolverException thrown if the URL is not a valid URL, the metadata can not be retrieved from
     *             the URL
     */
    public FileBackedHTTPMetadataResolver(@Nullable final Timer backgroundTaskTimer, @Nonnull final HttpClient client,
            @Nonnull final String metadataURL, @Nonnull final String backupFilePath) throws ResolverException {
        super(backgroundTaskTimer, client, metadataURL);
        
        backupFileInitNextRefreshDelay = Duration.ofSeconds(5);
        
        metadataBackupFile = new File(backupFilePath);
    }
    
    /**
     * Get the flag indicating whether metadata load during initialization was from backup file.
     * 
     * @return true if initial load was from backup file, false otherwise
     */
    public boolean isInitializedFromBackupFile() {
        return initializedFromBackupFile;
    }

    /**
     * Get the flag indicating whether initialization should first attempt to load metadata from backup file,
     * if it exists.
     * 
     * <p>Defaults to: true.</p>
     * 
     * @return true if should initialize from backup file, false otherwise
     */
    public boolean isInitializeFromBackupFile() {
        return initializeFromBackupFile;
    }

    /**
     * Set the flag indicating whether initialization should first attempt to load metadata from backup file,
     * if it exists.
     * 
     * <p>Defaults to: true.</p>
     * 
     * @param flag true if should initialize from backup file, false otherwise
     */
    public void setInitializeFromBackupFile(final boolean flag) {
        checkSetterPreconditions();
        
        initializeFromBackupFile = flag;
    }

    /**
     * Get the duration after which to schedule next refresh, when initialized from backup file.
     * 
     * <p>Defaults to 5s.</p>
     * 
     * @return the duration
     */
    @Nonnull public Duration getBackupFileInitNextRefreshDelay() {
        return backupFileInitNextRefreshDelay;
    }

    /**
     * Set the duration after which to schedule next refresh, when initialized from backup file.
     * 
     * <p>Defaults to 5s.</p>
     * 
     * @param delay the next refresh delay
     */
    public void setBackupFileInitNextRefreshDelay(@Nonnull final Duration delay) {
        checkSetterPreconditions();

        Constraint.isNotNull(delay, "Backup file init next refresh delay cannot be null");
        Constraint.isFalse(delay.isNegative() || delay.isZero(),
                "Backup file init next refresh delay must be greater than 0");
        
        backupFileInitNextRefreshDelay = delay;
    }

    /** {@inheritDoc} */
    @Override
    protected void initMetadataResolver() throws ComponentInitializationException {
        try {
            validateBackupFile(metadataBackupFile);
        } catch (final ResolverException e) {
            if (isFailFastInitialization()) {
                log.error("{} Metadata backup file path was invalid, initialization is fatal", getLogPrefix());
                throw new ComponentInitializationException("Metadata backup file path was invalid", e);
            }
            log.error("{} Metadata backup file path was invalid, continuing without known good backup file", 
                    getLogPrefix());
        }
        
        try {
            initializing = true;
            super.initMetadataResolver();
        } finally {
            initializing = false;
        }
    }

    /**
     * Sets the file used to backup metadata. The given file path is checked to see if it is a read/writable file if it
     * exists or if can be created if it does not exist.
     * 
     * @param backupFilePath path to the backup file
     * 
     * @throws ResolverException thrown if the backup file is not read/writable or creatable
     */
    protected void setBackupFile(@Nonnull final String backupFilePath) throws ResolverException {
        checkSetterPreconditions();

        metadataBackupFile = new File(backupFilePath);
    }

    /**
     * Validate the basic properties of the specified metadata backup file, for example that it 
     * exists and/or can be created; that it is not a directory; and that it is readable and writable.
     *
     * @param backupFile the file to evaluate
     * @throws ResolverException if file does not pass basic properties required of a metadata backup file
     */
    protected void validateBackupFile(@Nonnull final File backupFile) throws ResolverException {
        if (!backupFile.exists()) {
            try {
                log.debug("{} Testing creation of backup file", getLogPrefix());
                backupFile.createNewFile();
            } catch (final IOException e) {
                final String msg = "Unable to create backup file " + backupFile.getAbsolutePath();
                log.error("{} {}: {}", getLogPrefix(), msg, e.getMessage());
                throw new ResolverException(msg, e);
            } finally {
                // Don't leave the empty test file lying around if it didin't originally exist.
                // On init, if not valid metadata, this will muck with attempting to first load 
                // from backup file instead of http.
                if (backupFile.exists()) {
                    final boolean deleted = backupFile.delete();
                    if (!deleted) {
                        log.debug("{} Deletion of test backup file failed", getLogPrefix());
                    }
                }
            }
        } else {
            if (backupFile.isDirectory()) {
                throw new ResolverException("Filepath " + backupFile.getAbsolutePath()
                + " is a directory and may not be used as a backup metadata file");
            }

            if (!backupFile.canRead()) {
                throw new ResolverException("Filepath " + backupFile.getAbsolutePath()
                + " exists but can not be read by this user");
            }

            if (!backupFile.canWrite()) {
                throw new ResolverException("Filepath " + backupFile.getAbsolutePath()
                + " exists but can not be written to by this user");
            }
        }
    }

// Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    @Nullable protected byte[] fetchMetadata() throws ResolverException {
        if (initializing && initializeFromBackupFile && metadataBackupFile.exists()) {
            log.info("{} On initialization, detected existing backup file, attempting load from that: {}",
                        getLogPrefix(), metadataBackupFile.getAbsolutePath());
            try {
                final byte[] backingData = Files.toByteArray(metadataBackupFile);
                if (backingData == null || backingData.length == 0) {
                    log.info("{} Backup file byte array was null or empty, continuing with normal HTTP fetch: {}", 
                            getLogPrefix(), metadataBackupFile.getAbsolutePath());
                } else {
                    log.info("{} Successfully initialized from backup file: {}", 
                            getLogPrefix(), metadataBackupFile.getAbsolutePath());
                    initializedFromBackupFile = true;
                    return backingData;
                }
            } catch (final IOException e) {
                log.warn("{} Error initializing from backup file, continuing with normal HTTP fetch", 
                        getLogPrefix(), e);
            }
        }
        
        try {
            return super.fetchMetadata();
        } catch (final ResolverException e) {
            if (getCachedOriginalMetadata() != null) {
                log.warn("{} Problem reading metadata from remote source; " 
                        + "detected existing cached metadata, skipping load of backup file", getLogPrefix());
                return null;
            }
            
            if (metadataBackupFile.exists()) {
                log.warn("{} Problem reading metadata from remote source, processing existing backup file: {}", 
                        getLogPrefix(), metadataBackupFile.getAbsolutePath());
                try {
                    return Files.toByteArray(metadataBackupFile);
                } catch (final IOException ioe) {
                    final String errMsg = "Unable to retrieve metadata from backup file "
                            + metadataBackupFile.getAbsolutePath();
                    log.error("{} {}: {}", getLogPrefix(), errMsg, ioe.getMessage());
                    throw new ResolverException(errMsg, ioe);
                }
            }
            log.error("{} Unable to read metadata from remote server and backup does not exist", getLogPrefix());
            throw new ResolverException("Unable to read metadata from remote server and backup does not exist");
        }
    }
// Checkstyle: CyclomaticComplexity ON

    /** {@inheritDoc} */
    @Nonnull protected MetadataFilterContext newFilterContext() {
        final MetadataFilterContext context = super.newFilterContext();
        if (initializing && initializedFromBackupFile) {
            MetadataSource metadataSource = context.get(MetadataSource.class);
            if (metadataSource == null) {
                metadataSource = new MetadataSource();
                context.add(metadataSource);
            }
            metadataSource.setTrusted(true);
        }
        return context;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected Duration computeNextRefreshDelay(@Nullable final Instant expectedExpiration) {
        if (initializing && initializedFromBackupFile) {
            log.debug("{} Detected initialization from backup file, scheduling next refresh from HTTP in {}ms", 
                    getLogPrefix(), getBackupFileInitNextRefreshDelay());
            return getBackupFileInitNextRefreshDelay();
        }
        return super.computeNextRefreshDelay(expectedExpiration);
    }

    /** {@inheritDoc} */
    @Override
    protected void postProcessMetadata(@Nonnull final byte[] metadataBytes, @Nonnull final Document metadataDom,
            @Nonnull final XMLObject originalMetadata, @Nullable final XMLObject filteredMetadata)
                    throws ResolverException {

        final File staging = new File(metadataBackupFile.getAbsolutePath() + ".staging");
        try {
            validateBackupFile(staging);
            validateBackupFile(metadataBackupFile);
            try (final FileOutputStream out = new FileOutputStream(staging)) {
                out.write(metadataBytes);
                out.flush();
            }

            try {
                java.nio.file.Files.move(staging.toPath(), metadataBackupFile.toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (final IOException e) {
                log.warn("{} Error moving metadata backup staging file into place: {}",
                        getLogPrefix(), staging.getAbsolutePath(), e);
            }
        } catch (final ResolverException|IOException e) {
            log.warn("{} Unable to write metadata to backup file: {}", 
                    getLogPrefix(), metadataBackupFile.getAbsoluteFile(), e);
        } finally {
            if (staging.exists()) {
                staging.delete();
            }
            super.postProcessMetadata(metadataBytes, metadataDom, originalMetadata, filteredMetadata);
        }
    }
    
}