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

package org.opensaml.saml.saml1.binding.encoding.impl;

import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.Base64;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.HTMLMessageEncoder;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.codec.HTMLEncoder;
import net.shibboleth.shared.codec.StringDigester;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.servlet.HttpServletSupport;
import net.shibboleth.shared.xml.SerializeSupport;

import jakarta.servlet.http.HttpServletResponse;

/**
 * SAML 1.X HTTP POST message encoder.
 */
public class HTTPPostEncoder extends BaseSAML1MessageEncoder implements HTMLMessageEncoder {
    
    /** Default template ID. */
    @Nonnull @NotEmpty public static final String DEFAULT_TEMPLATE_ID = "/templates/saml1-post-binding.vm";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPPostEncoder.class);

    /** Velocity engine used to evaluate the template when performing POST encoding. */
    @NonnullAfterInit private VelocityEngine velocityEngine;

    /** ID of the velocity template used when performing POST encoding. */
    @NonnullAfterInit private String velocityTemplateId;
    
    /** Digester for CSP hashes. */
    @Nullable private StringDigester cspDigester;

    /** Generator for CSP nonces. */
    @Nullable private IdentifierGenerationStrategy cspNonceGenerator;
    
    /** Constructor. */
    public HTTPPostEncoder() {
        setVelocityTemplateId(DEFAULT_TEMPLATE_ID);
    }

    /** {@inheritDoc} */
    @Nonnull public String getBindingURI() {
        return SAMLConstants.SAML1_POST_BINDING_URI;
    }

    /**
     * Get the VelocityEngine instance.
     * 
     * @return return the VelocityEngine instance
     */
    @NonnullAfterInit public VelocityEngine getVelocityEngine() {
        return velocityEngine;
    }

    /**
     * Set the VelocityEngine instance.
     * 
     * @param newVelocityEngine the new VelocityEngine instane
     */
    public void setVelocityEngine(@Nullable final VelocityEngine newVelocityEngine) {
        checkSetterPreconditions();
        velocityEngine = newVelocityEngine;
    }
    
    /**
     * Get the Velocity template id.
     * 
     * <p>Defaults to {@link #DEFAULT_TEMPLATE_ID}.</p>
     * 
     * @return return the Velocity template id
     */
    @NonnullAfterInit public String getVelocityTemplateId() {
        return velocityTemplateId;
    }

    /**
     * Set the Velocity template id.
     * 
     * <p>Defaults to {@link #DEFAULT_TEMPLATE_ID}.</p>
     * 
     * @param newVelocityTemplateId the new Velocity template id
     */
    public void setVelocityTemplateId(@Nullable final String newVelocityTemplateId) {
        checkSetterPreconditions();
        velocityTemplateId = newVelocityTemplateId;
    }
    
    /** {@inheritDoc} */
    public void setCSPDigester(@Nullable final StringDigester digester) {
        checkSetterPreconditions();
        cspDigester = digester;
    }
    
    /** {@inheritDoc} */
    public void setCSPNonceGenerator(@Nullable final IdentifierGenerationStrategy strategy) {
        checkSetterPreconditions();
        cspNonceGenerator = strategy;
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (velocityEngine == null) {
            throw new ComponentInitializationException("VelocityEngine must be supplied");
        }
        if (velocityTemplateId == null) {
            throw new ComponentInitializationException("Velocity template id must be supplied");
        }
    }

    /** {@inheritDoc} */
    protected void doEncode() throws MessageEncodingException {
        final MessageContext messageContext = getMessageContext();

        final Object outboundMessage = messageContext.getMessage();
        if (outboundMessage == null || !(outboundMessage instanceof SAMLObject)) {
            throw new MessageEncodingException("No outbound SAML message contained in message context");
        }
        final String endpointURL = getEndpointURL(messageContext).toString();
        
        postEncode(messageContext, endpointURL);
    }

    /**
     * Base64 and POST encodes the outbound message and writes it to the outbound transport.
     * 
     * @param messageContext current message context
     * @param endpointURL endpoint URL to encode message to
     * 
     * @throws MessageEncodingException thrown if there is a problem encoding the message
     */
    protected void postEncode(@Nonnull final MessageContext messageContext, @Nonnull final String endpointURL) 
            throws MessageEncodingException {
        log.debug("Invoking velocity template to create POST body");

        try {
            final VelocityContext context = new VelocityContext();
            final XMLObject message = (XMLObject) messageContext.getMessage();
            assert message != null;

            final String encodedEndpointURL = HTMLEncoder.encodeForHTMLAttribute(endpointURL);
            log.debug("Encoding action url of '{}' with encoded value '{}'", endpointURL, encodedEndpointURL);
            context.put("action", encodedEndpointURL);
            context.put("binding", getBindingURI());
            
            if (cspDigester != null) {
                log.trace("Adding CSP digester to context");
                context.put("cspDigester", cspDigester);
            }
            if (cspNonceGenerator != null) {
                log.trace("Adding CSP nonce generator to context");
                context.put("cspNonce", cspNonceGenerator);
            }

            log.debug("Marshalling and Base64 encoding SAML message");
            final String messageXML = SerializeSupport.nodeToString(marshallMessage(message));
            final String encodedMessage = Base64.getEncoder().encodeToString(messageXML.getBytes("UTF-8"));
            context.put("SAMLResponse", encodedMessage);

            final String relayState = SAMLBindingSupport.getRelayState(messageContext);
            if (relayState != null) {
                final String encodedRelayState = HTMLEncoder.encodeForHTMLAttribute(relayState);
                log.debug("Setting TARGET parameter to: '{}', encoded as '{}'", relayState, encodedRelayState);
                context.put("TARGET", encodedRelayState);
            }
            
            final HttpServletResponse response = getHttpServletResponse();
            assert response != null;
            context.put("response", response);
            
            HttpServletSupport.addNoCacheHeaders(response);
            HttpServletSupport.setUTF8Encoding(response);
            HttpServletSupport.setContentType(response, "text/html");

            try (final Writer out = new OutputStreamWriter(response.getOutputStream(), "UTF-8")) {
                velocityEngine.mergeTemplate(velocityTemplateId, "UTF-8", context, out);
                out.flush();
            }
        } catch (final UnsupportedEncodingException e) {
            log.error("UTF-8 encoding is not supported, this VM is not Java compliant");
            throw new MessageEncodingException("Unable to encode message, UTF-8 encoding is not supported");
        } catch (final Exception e) {
            log.error("Error invoking velocity template: {}", e.getMessage());
            throw new MessageEncodingException("Error creating output document", e);
        }
    }

}