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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.opensaml.saml.metadata.resolver.RemoteMetadataResolver;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.slf4j.Logger;

import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * A metadata provider that pulls metadata using an HTTP GET. Metadata is cached until one of these criteria is met:
 * <ul>
 * <li>The smallest cacheDuration within the metadata is exceeded</li>
 * <li>The earliest validUntil time within the metadata is exceeded</li>
 * <li>The maximum cache duration is exceeded</li>
 * </ul>
 * 
 * Metadata is filtered prior to determining the cache expiration data. This allows a filter to remove XMLObjects that
 * may effect the cache duration but for which the user of this provider does not care about.
 * 
 * It is the responsibility of the caller to re-initialize, via {@link #initialize()}, if any properties of this
 * provider are changed.
 */
public class HTTPMetadataResolver extends AbstractReloadingMetadataResolver implements RemoteMetadataResolver {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPMetadataResolver.class);

    /** HTTP Client used to pull the metadata. */
    @Nonnull private final HttpClient httpClient;

    /** URL to the Metadata. */
    @Nonnull private final URI metadataURI;

    /** The ETag provided when the currently cached metadata was fetched. */
    @Nullable private String cachedMetadataETag;

    /** The Last-Modified information provided when the currently cached metadata was fetched. */
    @Nullable private String cachedMetadataLastModified;

    /** Optional HttpClient security parameters.*/
    @Nullable private HttpClientSecurityParameters httpClientSecurityParameters;

    /**
     * Constructor.
     * 
     * @param client HTTP client used to pull in remote metadata
     * @param metadataURL URL to the remove remote metadata
     * 
     * @throws ResolverException thrown if the HTTP client is null or the metadata URL provided is invalid
     */
    public HTTPMetadataResolver(@Nonnull final HttpClient client, final String metadataURL) throws ResolverException {
        this(null, client, metadataURL);
    }

    /**
     * Constructor.
     * 
     * @param backgroundTaskTimer timer used to schedule background metadata refresh tasks
     * @param client HTTP client used to pull in remote metadata
     * @param metadataURL URL to the remove remote metadata
     * 
     * @throws ResolverException thrown if the HTTP client is null or the metadata URL provided is invalid
     */
    public HTTPMetadataResolver(final Timer backgroundTaskTimer, @Nonnull final HttpClient client,
            final String metadataURL) throws ResolverException {
        super(backgroundTaskTimer);

        httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");

        try {
            metadataURI = new URI(metadataURL);
        } catch (final URISyntaxException e) {
            throw new ResolverException("Illegal URL syntax", e);
        }
    }

    /** {@inheritDoc} */
    @Nonnull public String getMetadataURI() {
        return metadataURI.toASCIIString();
    }
        
    /**
     * Get the instance of {@link HttpClientSecurityParameters} which provides various parameters to influence
     * the security behavior of the HttpClient instance.
     * 
     * @return the parameters instance, or null
     */
    @Nullable protected HttpClientSecurityParameters getHttpClientSecurityParameters() {
        return httpClientSecurityParameters;
    }
    
    /**
     * Set an instance of {@link HttpClientSecurityParameters} which provides various parameters to influence
     * the security behavior of the HttpClient instance.
     * 
     * <p>
     * For all TLS-related parameters, must be used in conjunction with an HttpClient instance 
     * which is configured with either a:
     * </p>
     *
     * <ul>
     * <li>
     * a {@link net.shibboleth.shared.httpclient.TLSSocketFactory}
     * </li>
     * <li>
     * {@link org.opensaml.security.httpclient.impl.SecurityEnhancedTLSSocketFactory} which wraps
     * an instance of {@link net.shibboleth.shared.httpclient.TLSSocketFactory}, with
     * the latter likely configured in a "no trust" configuration.  This variant is required if either a
     * trust engine or a client TLS credential is to be used.
     * </li>
     * </ul>
     * 
     * <p>
     * For convenience methods for building a 
     * {@link net.shibboleth.shared.httpclient.TLSSocketFactory}, 
     * see {@link net.shibboleth.shared.httpclient.HttpClientSupport}.
     * </p>
     * 
     * <p>
     * If the appropriate TLS socket factory is not configured and a trust engine is specified, 
     * then this will result in no TLS trust evaluation being performed and a 
     * {@link ResolverException} will ultimately be thrown.
     * </p>
     *
     * @param params the security parameters
     */
    public void setHttpClientSecurityParameters(@Nullable final HttpClientSecurityParameters params) {
        checkSetterPreconditions();

        httpClientSecurityParameters = params;
    }

    /** {@inheritDoc} */
    @Override
    protected String getMetadataIdentifier() {
        return metadataURI.toString();
    }

    /**
     * Gets the metadata document from the remote server.
     * 
     * @return the metadata from remote server, or null if the metadata document has not changed since the last
     *         retrieval
     * 
     * @throws ResolverException thrown if there is a problem retrieving the metadata from the remote server
     */
    @Override
    @Nullable protected byte[] fetchMetadata() throws ResolverException {
        final HttpGet httpGet = buildHttpGet();
        final HttpClientContext context = buildHttpClientContext(httpGet);

        log.debug("{} Attempting to fetch metadata document from '{}'", getLogPrefix(), metadataURI);
        try (final ClassicHttpResponse response = httpClient.executeOpen(null, httpGet, context)) {
            
            HttpClientSecuritySupport.checkTLSCredentialEvaluated(context, metadataURI.getScheme());
            final int httpStatusCode = response.getCode();

            if (httpStatusCode == HttpStatus.SC_NOT_MODIFIED) {
                log.debug("{} Metadata document from '{}' has not changed since last retrieval", 
                        getLogPrefix(), getMetadataURI());
                return null;
            }

            if (httpStatusCode != HttpStatus.SC_OK) {
                final String errMsg =
                        "Non-ok status code " + httpStatusCode + " returned from remote metadata source " + metadataURI;
                log.error("{} " + errMsg, getLogPrefix());
                throw new ResolverException(errMsg);
            }

            processConditionalRetrievalHeaders(response);

            final byte[] rawMetadata = getMetadataBytesFromResponse(response);
            log.debug("{} Successfully fetched {} bytes of metadata from {}", 
                    getLogPrefix(), rawMetadata.length, getMetadataURI());

            return rawMetadata;
        } catch (final IOException e) {
            final String errMsg = "Error retrieving metadata from " + metadataURI;
            log.error("{} {}: {}", getLogPrefix(), errMsg, e.getMessage());
            throw new ResolverException(errMsg, e);
        }
    }

    /**
     * Builds the {@link HttpGet} instance used to fetch the metadata. The returned method advertises support for GZIP
     * and deflate compression, enables conditional GETs if the cached metadata came with either an ETag or
     * Last-Modified information, and sets up basic authentication if such is configured.
     * 
     * @return the constructed HttpGet instance
     */
    @Nonnull protected HttpGet buildHttpGet() {
        final HttpGet getMethod = new HttpGet(getMetadataURI());

        if (cachedMetadataETag != null) {
            getMethod.setHeader("If-None-Match", cachedMetadataETag);
        }
        if (cachedMetadataLastModified != null) {
            getMethod.setHeader("If-Modified-Since", cachedMetadataLastModified);
        }

        return getMethod;
    }
    
    /**
     * Build the {@link HttpClientContext} instance which will be used to invoke the {@link HttpClient} request.
     * 
     * @param request the current HTTP request
     * 
     * @return a new instance of {@link HttpClientContext}
     */
    @Nonnull protected HttpClientContext buildHttpClientContext(@Nonnull final ClassicHttpRequest request) {
        final HttpClientContext context =
                HttpClientSecuritySupport.buildHttpClientContext(httpClientSecurityParameters);
        
        HttpClientSecuritySupport.addDefaultTLSTrustEngineCriteria(context, request);
        
        return context;
    }

    /**
     * Records the ETag and Last-Modified headers, from the response, if they are present.
     * 
     * @param response GetMethod containing a valid HTTP response
     */
    protected void processConditionalRetrievalHeaders(@Nonnull final ClassicHttpResponse response) {
        Header httpHeader = response.getFirstHeader("ETag");
        if (httpHeader != null) {
            cachedMetadataETag = httpHeader.getValue();
        }

        httpHeader = response.getFirstHeader("Last-Modified");
        if (httpHeader != null) {
            cachedMetadataLastModified = httpHeader.getValue();
        }
    }

    /**
     * Extracts the raw metadata bytes from the response taking in to account possible deflate and GZip compression.
     * 
     * @param response GetMethod containing a valid HTTP response
     * 
     * @return the raw metadata bytes
     * 
     * @throws ResolverException thrown if there is a problem getting the raw metadata bytes from the response
     */
    @Nonnull protected byte[] getMetadataBytesFromResponse(@Nonnull final ClassicHttpResponse response)
            throws ResolverException {
        log.debug("{} Attempting to extract metadata from response to request for metadata from '{}'", 
                getLogPrefix(), getMetadataURI());
        try (final HttpEntity entity = response.getEntity()) {
            return inputstreamToByteArray(entity.getContent());
        } catch (final IOException e) {
            log.error("{} Unable to read response: {}", getLogPrefix(), e.getMessage());
            throw new ResolverException("Unable to read response", e);
        }
    }
}