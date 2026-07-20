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

package org.opensaml.soap.client.http;

import static org.opensaml.security.httpclient.HttpClientSecurityConstants.CONTEXT_KEY_CRITERIA_SET;
import static org.opensaml.security.httpclient.HttpClientSecurityConstants.CONTEXT_KEY_SERVER_TLS_FAILURE_IS_FATAL;
import static org.opensaml.security.httpclient.HttpClientSecurityConstants.CONTEXT_KEY_TRUST_ENGINE;

import java.io.IOException;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLException;

import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.httpclient.HttpClientRequestContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.httpclient.HttpClientResponseMessageDecoder;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.encoder.httpclient.HttpClientRequestMessageEncoder;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.opensaml.security.messaging.HttpClientSecurityContext;
import org.opensaml.soap.client.SOAPClient;
import org.opensaml.soap.client.SOAPClientContext;
import org.opensaml.soap.client.SOAPFaultException;
import org.opensaml.soap.common.SOAP11FaultDecodingException;
import org.opensaml.soap.common.SOAPException;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.resolver.CriteriaSet;

/**
 * SOAP client that is based on {@link HttpClientMessagePipeline}.
 */
@ThreadSafe
public abstract class AbstractPipelineHttpSOAPClient 
        extends AbstractInitializableComponent implements SOAPClient {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractPipelineHttpSOAPClient.class);

    /** HTTP client used to send requests and receive responses. */
    @NonnullAfterInit private HttpClient httpClient;
    
    /** HTTP client security parameters. */
    @Nullable private HttpClientSecurityParameters httpClientSecurityParameters;
    
    /** Strategy for building the criteria set which is input to the TLS trust engine. */
    @Nullable private Function<InOutOperationContext,CriteriaSet> tlsCriteriaSetStrategy;

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (httpClient == null) {
            throw new ComponentInitializationException("HttpClient cannot be null");
        } 
    }
    
    /**
     * Get the client used to make outbound HTTP requests.
     * 
     * @return the client instance
     */
    @NonnullAfterInit public HttpClient getHttpClient() {
        return httpClient;
    }

    /**
     * Set the client used to make outbound HTTP requests.
     * 
     * <p>This client SHOULD employ a thread-safe {@link HttpClient} and may be shared with other objects.</p>
     * 
     * @param client client object
     */
    public void setHttpClient(@Nonnull final HttpClient client) {
        checkSetterPreconditions();
        
        httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");
    }
    
    /**
     * Get the optional client security parameters.
     * 
     * @return the client security parameters, or null
     */
    @Nullable public HttpClientSecurityParameters getHttpClientSecurityParameters() {
        return httpClientSecurityParameters;
    }

    /**
     * Set the optional client security parameters.
     * 
     * @param params the new client security parameters
     */
    public void setHttpClientSecurityParameters(@Nullable final HttpClientSecurityParameters params) {
        checkSetterPreconditions();
        
        httpClientSecurityParameters = params;
    }
    
    /**
     * Get the strategy function which builds the dynamically-populated criteria set which is 
     * input to the TLS TrustEngine, if no static criteria set is supplied either via context 
     * or locally-configured {@link HttpClientSecurityParameters}.
     * 
     * @return the strategy function, or null
     */
    @Nullable public Function<InOutOperationContext,CriteriaSet> getTLSCriteriaSetStrategy() {
        return tlsCriteriaSetStrategy;
    }
    
    /**
     * Set the strategy function which builds the dynamically-populated criteria set which is 
     * input to the TLS TrustEngine, if no static criteria set is supplied either via context
     * or locally-configured {@link HttpClientSecurityParameters}.
     * 
     * @param function the strategy function, or null
     */
    public void setTLSCriteriaSetStrategy(@Nullable final Function<InOutOperationContext,CriteriaSet> function) {
        checkSetterPreconditions();
        
        tlsCriteriaSetStrategy = function;
    }
    
    /** {@inheritDoc} */
    // Checkstyle: CyclomaticComplexity|MethodLength OFF
    public void send(@Nonnull @NotEmpty final String endpoint, @Nonnull final InOutOperationContext operationContext)
            throws SOAPException, SecurityException {
        Constraint.isNotNull(endpoint, "Endpoint cannot be null");
        Constraint.isNotNull(operationContext, "Operation context cannot be null");
        
        HttpClientMessagePipeline pipeline = null;
        try {
            // Store the endpoint URI
            operationContext.ensureSubcontext(SOAPClientContext.class).setDestinationURI(endpoint);
            
            // Pipeline resolution
            pipeline = resolvePipeline(operationContext);
            
            // Outbound payload handling
            MessageHandler handler = pipeline.getOutboundPayloadMessageHandler();
            if (handler != null) {
                handler.invoke(operationContext.ensureOutboundMessageContext());
            }
            
            final ClassicHttpRequest httpRequest = buildHttpRequest(endpoint, operationContext);
            // Request encoding + outbound transport handling
            final HttpClientRequestMessageEncoder encoder = pipeline.getEncoder();
            encoder.setHttpRequest(httpRequest);
            encoder.setMessageContext(operationContext.getOutboundMessageContext());
            encoder.initialize();
            encoder.prepareContext();
            
            // Outbound transport handling.
            handler = pipeline.getOutboundTransportMessageHandler();
            if (handler != null) {
                handler.invoke(operationContext.ensureOutboundMessageContext());
            }
            
            encoder.encode();
            
            // HttpClient execution
            final HttpClientContext httpContext = buildHttpContext(httpRequest, operationContext);
            try (final ClassicHttpResponse httpResponse = getHttpClient().executeOpen(null, httpRequest, httpContext)) {
                HttpClientSecuritySupport.checkTLSCredentialEvaluated(httpContext, httpRequest.getScheme());

                // Response decoding
                final HttpClientResponseMessageDecoder decoder = pipeline.getDecoder();
                decoder.setHttpResponse(httpResponse);
                decoder.initialize();
                decoder.decode();
                operationContext.setInboundMessageContext(decoder.getMessageContext());
            }
            
            // Inbound message handling
            
            handler = pipeline.getInboundMessageHandler();
            if (handler != null) {
                handler.invoke(operationContext.ensureInboundMessageContext());
            }
            
        } catch (final SOAP11FaultDecodingException e) {
            final SOAPFaultException faultException = new SOAPFaultException(e.getMessage(), e);
            faultException.setFault(e.getFault());
            throw faultException;
        } catch (final SSLException e) {
            throw new SecurityException("Problem establising TLS connection to: " + endpoint, e);
        } catch (final ComponentInitializationException e) {
            throw new SOAPException("Problem initializing a SOAP client component", e);
        } catch (final MessageEncodingException e) {
            throw new SOAPException("Problem encoding SOAP request message to: " + endpoint, e);
        } catch (final MessageDecodingException e) {
            throw new SOAPException("Problem decoding SOAP response message from: " + endpoint, e);
        } catch (final MessageHandlerException e) {
            throw new SOAPException("Problem handling SOAP message exchange with: " + endpoint, e);
        } catch (final ClientProtocolException e) {
            throw new SOAPException("Client protocol problem sending SOAP request message to: " + endpoint, e);
        } catch (final IOException e) {
            throw new SOAPException("I/O problem with SOAP message exchange with: " + endpoint, e);
        }
    }
    // Checkstyle: CyclomaticComplexity|MethodLength ON
    
    /**
     * Resolve and return a new instance of the {@link HttpClientMessagePipeline} to be processed.
     * 
     * <p>
     * Each call to this (factory) method MUST produce a new instance of the pipeline.
     * </p>
     * 
     * <p>
     * The default behavior is to simply call {@link #newPipeline()}.
     * </p>
     * 
     * @param operationContext the current operation context
     * 
     * @return a new pipeline instance
     * 
     * @throws SOAPException if there is an error obtaining a new pipeline instance
     */
    @Nonnull protected HttpClientMessagePipeline resolvePipeline(@Nonnull final InOutOperationContext operationContext)
            throws SOAPException {
        try {
            return newPipeline();
        } catch (final SOAPException e) {
            log.warn("Problem resolving pipeline instance: {}", e.getMessage());
            throw e;
        } catch (final Exception e) {
            // This is to handle RuntimeExceptions, for example thrown by Spring dynamic factory approaches
            log.warn("Problem resolving pipeline instance: {}", e.getMessage());
            throw new SOAPException("Could not resolve pipeline", e);
        }
    }
    
    /**
     * Get a new instance of the {@link HttpClientMessagePipeline} to be processed.
     * 
     * <p>
     * Each call to this (factory) method MUST produce a new instance of the pipeline.
     * </p>
     * 
     * @return the new pipeline instance
     * 
     * @throws SOAPException if there is an error obtaining a new pipeline instance
     */
    @Nonnull protected abstract HttpClientMessagePipeline newPipeline() 
            throws SOAPException;
        
    /**
     * Build the {@link ClassicHttpRequest} instance to be executed by the HttpClient.
     * 
     * @param endpoint the endpoint to which the message will be sent
     * @param operationContext the current operation context
     * @return the HTTP request to be executed
     */
    @Nonnull protected ClassicHttpRequest buildHttpRequest(@Nonnull @NotEmpty final String endpoint, 
            @Nonnull final InOutOperationContext operationContext) {
        return new HttpPost(endpoint);
    }

    /**
     * Build the {@link HttpClientContext} instance to be used by the HttpClient.
     * 
     * @param request the HTTP client request
     * @param operationContext the current operation context
     * @return the client context instance
     */
    @Nonnull protected HttpClientContext buildHttpContext(@Nonnull final ClassicHttpRequest request, 
            @Nonnull final InOutOperationContext operationContext) {
        
        final HttpClientContext clientContext = resolveClientContext(operationContext);
        
        final HttpClientSecurityParameters contextSecurityParameters =
                resolveContextSecurityParameters(operationContext);
        
        HttpClientSecuritySupport.marshalSecurityParameters(clientContext, contextSecurityParameters, false);
        
        HttpClientSecuritySupport.marshalSecurityParameters(clientContext, getHttpClientSecurityParameters(), false);
        
        if ("https".equalsIgnoreCase(request.getScheme()) 
                && clientContext.getAttribute(CONTEXT_KEY_TRUST_ENGINE) != null) {
            
            if (clientContext.getAttribute(CONTEXT_KEY_CRITERIA_SET) == null) {
                clientContext.setAttribute(CONTEXT_KEY_CRITERIA_SET, 
                        buildTLSCriteriaSet(request, operationContext));
            }
            
            // Default this false if not explicitly set, as pipeline handlers will generally 
            // want to evaluate the result themselves. Can set explicitly on this client's params
            // instance if want to override.
            if (clientContext.getAttribute(CONTEXT_KEY_SERVER_TLS_FAILURE_IS_FATAL) == null) {
                clientContext.setAttribute(CONTEXT_KEY_SERVER_TLS_FAILURE_IS_FATAL, Boolean.FALSE);
            }
        }
        
        HttpClientSecuritySupport.addDefaultTLSTrustEngineCriteria(clientContext, request);
        
        return clientContext;
    }
    
    /**
     * Resolve the {@link HttpClientSecurityParameters} instance present in the current operation context.
     * 
     * <p>
     * The default implementation returns the outbound subcontext value 
     * {@link HttpClientSecurityContext#getSecurityParameters()}.
     * </p>
     * 
     * <p>
     * Note that any values supplied via this instance will override those supplied locally via
     * {@link #setHttpClientSecurityParameters(HttpClientSecurityParameters)}.
     * </p>
     * 
     * @param operationContext the current operation context
     * @return the client security parameters resolved from the current operation context, or null
     */
    @Nullable protected HttpClientSecurityParameters resolveContextSecurityParameters(
            @Nonnull final InOutOperationContext operationContext) {
        final HttpClientSecurityContext securityContext = 
                operationContext.ensureOutboundMessageContext().getSubcontext(HttpClientSecurityContext.class);
        if (securityContext != null) {
            return securityContext.getSecurityParameters();
        }
        return null;
    }

    /**
     * Resolve the effective {@link HttpClientContext} instance to use for the current request.
     * 
     * <p>
     * The default implementation first attempts to resolve the outbound subcontext value
     * {@link HttpClientRequestContext#getHttpClientContext()}. If no context value is present,
     * a new empty context instance will be returned via {@link HttpClientContext#create()}.
     * </p>
     * 
     * <p>
     * Note that any security-related attributes supplied directly the client context returned here
     * will override the corresponding values supplied via both operation context and locally-configured
     * instances of {@link HttpClientSecurityParameters}.
     * </p>
     * 
     * @param operationContext the current operation context
     * @return the effective client context instance to use
     */
    @Nonnull protected HttpClientContext resolveClientContext(@Nonnull final InOutOperationContext operationContext) {
        final HttpClientRequestContext requestContext = 
                operationContext.ensureOutboundMessageContext().ensureSubcontext(HttpClientRequestContext.class);
        
        HttpClientContext clientCtx = requestContext.getHttpClientContext();
        if (clientCtx == null) {
            clientCtx = HttpClientContext.create();
            requestContext.setHttpClientContext(clientCtx);
        }
        
        assert clientCtx != null;
        return clientCtx;
    }

    /**
     * Build the dynamic {@link CriteriaSet} instance to be used for TLS trust evaluation.
     * 
     * @param request the HTTP client request
     * @param operationContext the current operation context
     * @return the new criteria set instance
     */
    @Nonnull protected CriteriaSet buildTLSCriteriaSet(@Nonnull final ClassicHttpRequest request, 
            @Nonnull final InOutOperationContext operationContext) {
        
        final CriteriaSet criteriaSet = new CriteriaSet();
        final Function<InOutOperationContext,CriteriaSet> strategy = getTLSCriteriaSetStrategy();
        if (strategy != null) {
            final CriteriaSet resolved = strategy.apply(operationContext);
            if (resolved != null) {
                criteriaSet.addAll(resolved);
            }
        }
        if (!criteriaSet.contains(UsageCriterion.class)) {
            criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
        }
        return criteriaSet;
    }

}