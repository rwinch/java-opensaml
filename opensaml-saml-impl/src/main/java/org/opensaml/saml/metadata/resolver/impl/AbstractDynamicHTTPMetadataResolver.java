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
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.Timer;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSource;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.slf4j.Logger;
import org.slf4j.MDC;

import com.google.common.base.Strings;
import com.google.common.io.ByteStreams;
import com.google.common.net.MediaType;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.collection.LazySet;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.net.MediaTypeSupport;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * Abstract subclass for dynamic metadata resolvers that implement metadata resolution based on HTTP requests.
 */
public abstract class AbstractDynamicHTTPMetadataResolver extends AbstractDynamicMetadataResolver {
    
    /** Default list of supported content MIME types. */
    @Nonnull @NotEmpty public static final String[] DEFAULT_CONTENT_TYPES = 
            new String[] {"application/samlmetadata+xml", "application/xml", "text/xml"};
    
    /** MDC attribute representing the current request URI. Will be available during the execution of the 
     * configured {@link HttpClientResponseHandler}. */
    @Nonnull @NotEmpty public static final String MDC_ATTRIB_CURRENT_REQUEST_URI = 
            AbstractDynamicHTTPMetadataResolver.class.getName() + ".currentRequestURI";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractDynamicHTTPMetadataResolver.class);
    
    /** HTTP Client used to pull the metadata. */
    @Nonnull private final HttpClient httpClient;
    
    /** List of supported MIME types for use in Accept request header and validation of 
     * response Content-Type header.*/
    @NonnullAfterInit private List<String> supportedContentTypes;
    
    /** Generated Accept request header value. */
    @NonnullAfterInit private String supportedContentTypesValue;
    
    /**Supported {@link MediaType} instances, constructed from the {@link #supportedContentTypes} list. */
    @NonnullAfterInit private Set<MediaType> supportedMediaTypes;
    
    /** HttpClient ResponseHandler instance to use. */
    @Nonnull private final HttpClientResponseHandler<XMLObject> responseHandler;
        
    /** Optional HttpClient security parameters.*/
    @Nullable private HttpClientSecurityParameters httpClientSecurityParameters;
    
    /**
     * Constructor.
     *
     * @param client the instance of {@link HttpClient} used to fetch remote metadata
     */
    public AbstractDynamicHTTPMetadataResolver(@Nonnull final HttpClient client) {
        this(null, client);
    }
    
    /**
     * Constructor.
     *
     * @param backgroundTaskTimer the {@link Timer} instance used to run resolver background managment tasks
     * @param client the instance of {@link HttpClient} used to fetch remote metadata
     */
    public AbstractDynamicHTTPMetadataResolver(@Nullable final Timer backgroundTaskTimer, 
            @Nonnull final HttpClient client) {
        super(backgroundTaskTimer);
        
        httpClient = Constraint.isNotNull(client, "HttpClient may not be null");
        
        // The default handler
        responseHandler = new BasicMetadataResponseHandler();
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
     * which is configured with either:
     * </p>
     * <ul>
     * <li>
     * a {@link net.shibboleth.shared.httpclient.TLSSocketFactory}
     * </li>
     * <li>
     * a {@link org.opensaml.security.httpclient.impl.SecurityEnhancedTLSSocketFactory} which wraps
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
    
    /**
     * Get the list of supported MIME {@link MediaType} instances used in validation of 
     * the response Content-Type header.
     * 
     * <p>
     * Is generated at init time from {@link #getSupportedContentTypes()}.
     * </p>
     * 
     * @return the supported content types
     */
    @NonnullAfterInit @NotLive @Unmodifiable
    protected Set<MediaType> getSupportedMediaTypes() {
        return supportedMediaTypes;
    }

    /**
     * Get the list of supported MIME types for use in Accept request header and validation of 
     * response Content-Type header.
     * 
     * @return the supported content types
     */
    @NonnullAfterInit @NotLive @Unmodifiable
    public List<String> getSupportedContentTypes() {
        return supportedContentTypes;
    }

    /**
     * Set the list of supported MIME types for use in Accept request header and validation of 
     * response Content-Type header. Values will be effectively lower-cased at runtime.
     * 
     * @param types the new supported content types to set
     */
    public void setSupportedContentTypes(@Nullable final List<String> types) {
        checkSetterPreconditions();
        if (types == null) {
            supportedContentTypes = CollectionSupport.emptyList();
        } else {
            supportedContentTypes = StringSupport.normalizeStringCollection(types)
                    .stream()
                    .filter(s -> s != null)
                    .map(String::toLowerCase)
                    .collect(Collectors.toUnmodifiableList());
        }
    }
    
    /** {@inheritDoc} */
    @Override
    protected void initMetadataResolver() throws ComponentInitializationException {
        super.initMetadataResolver();
        
        if (getSupportedContentTypes() == null) {
            setSupportedContentTypes(Arrays.asList(DEFAULT_CONTENT_TYPES));
        }
        
        if (!getSupportedContentTypes().isEmpty()) {
            supportedContentTypesValue = StringSupport.listToStringValue(getSupportedContentTypes(), ", ");
            supportedMediaTypes = new LazySet<>();
            for (final String contentType : getSupportedContentTypes()) {
                supportedMediaTypes.add(MediaType.parse(contentType));
            }
        } else {
            supportedMediaTypes = CollectionSupport.emptySet();
        }
        
        log.debug("{} Supported content types are: {}", getLogPrefix(), getSupportedContentTypes());
    }

    /** {@inheritDoc} */
    @Override
    @Nullable protected XMLObject fetchFromOriginSource(@Nullable final CriteriaSet criteria) 
            throws IOException {
            
        final ClassicHttpRequest request = buildHttpRequest(criteria);
        if (request == null) {
            log.debug("{} Could not build request based on input criteria, unable to query", getLogPrefix());
            return null;
        }
        
        final HttpClientContext context = buildHttpClientContext(request);
        
        try {
            MDC.put(MDC_ATTRIB_CURRENT_REQUEST_URI, request.getRequestUri());
            final XMLObject result = httpClient.execute(request, context, responseHandler);
            HttpClientSecuritySupport.checkTLSCredentialEvaluated(context, request.getScheme());
            return result;
        } finally {
            MDC.remove(MDC_ATTRIB_CURRENT_REQUEST_URI);
        }
    }
        
    /**
     * Build an appropriate instance of {@link ClassicHttpRequest} based on the input criteria set.
     * 
     * @param criteria the input criteria set
     * @return the newly constructed request, or null if it can not be built from the supplied criteria
     */
    @Nullable protected ClassicHttpRequest buildHttpRequest(@Nullable final CriteriaSet criteria) {
        final String url = buildRequestURL(criteria);
        log.debug("{} Built request URL of: {}", getLogPrefix(), url);
        
        if (url == null) {
            log.debug("{} Could not construct request URL from input criteria, unable to query", getLogPrefix());
            return null;
        }
            
        final HttpGet getMethod = new HttpGet(url);
        
        if (!Strings.isNullOrEmpty(supportedContentTypesValue)) {
            getMethod.addHeader("Accept", supportedContentTypesValue);
        }
        
        // TODO other headers ?
        
        return getMethod;
    }

    /**
     * Build the request URL based on the input criteria set.
     * 
     * @param criteria the input criteria set
     * @return the request URL, or null if it can not be built based on the supplied criteria
     */
    @Nullable protected abstract String buildRequestURL(@Nullable final CriteriaSet criteria);
        
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
     * Basic HttpClient response handler for processing metadata fetch requests.
     */
    public class BasicMetadataResponseHandler implements HttpClientResponseHandler<XMLObject> {

        /** {@inheritDoc} */
        public XMLObject handleResponse(final ClassicHttpResponse response) throws IOException {
            
            final int httpStatusCode = response.getCode();
            
            final String currentRequestURI = MDC.get(MDC_ATTRIB_CURRENT_REQUEST_URI);
            
            // TODO should we be seeing/doing this? Probably not if we don't do conditional GET.
            // But we will if we do pre-emptive refreshing of metadata in background thread.
            if (httpStatusCode == HttpStatus.SC_NOT_MODIFIED) {
                log.debug("{} Metadata document from '{}' has not changed since last retrieval", 
                        getLogPrefix(), currentRequestURI);
                return null;
            }

            if (httpStatusCode != HttpStatus.SC_OK) {
                log.warn("{} Non-ok status code '{}' returned from remote metadata source: {}", 
                        getLogPrefix(), httpStatusCode, currentRequestURI);
                return null;
            }
            
            try {
                validateHttpResponse(response);
            } catch (final ResolverException e) {
                log.error("{} Problem validating dynamic metadata HTTP response", getLogPrefix(), e);
                return null;
            }
            
            try (final HttpEntity entity = response.getEntity()) {
                try (final InputStream ins = entity.getContent()) {
                    // TODO why are we buffering the InputStream to byte[] like this,
                    // rather than just unmarshalling it directly?
                    final byte[] source = ByteStreams.toByteArray(ins);
                    assert source != null;
                    try (final ByteArrayInputStream bais = new ByteArrayInputStream(source)) {
                        final XMLObject xmlObject = unmarshallMetadata(bais);
                        xmlObject.getObjectMetadata().put(new XMLObjectSource(source));
                        return xmlObject;
                    }
                }
            } catch (final IOException | UnmarshallingException e) {
                log.error("{} Error unmarshalling HTTP response stream", getLogPrefix(), e);
                return null;
            }
                
        }
        
        /**
         * Validate the received HTTP response instance, such as checking for supported content types.
         * 
         * @param response the received response
         * @throws ResolverException if the response was not valid, or if there is a fatal error validating the response
         */
        protected void validateHttpResponse(@Nonnull final ClassicHttpResponse response) throws ResolverException {
            if (!getSupportedMediaTypes().isEmpty()) {
                final String contentType = StringSupport.trimOrNull(response.getEntity().getContentType());
                log.debug("{} Saw raw Content-Type from response header '{}'", getLogPrefix(), contentType);
                
                if (!MediaTypeSupport.validateContentType(contentType, getSupportedMediaTypes(), true, false)) {
                    throw new ResolverException("HTTP response specified an unsupported Content-Type MIME type: " 
                            + contentType);
                }
            }
        }
            
    }

}