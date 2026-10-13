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

package org.opensaml.saml.saml2.binding.encoding.impl;

import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.Base64;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.HTMLMessageEncoder;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.slf4j.Logger;
import org.w3c.dom.Element;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.codec.HTMLEncoder;
import net.shibboleth.shared.codec.StringDigester;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.servlet.HttpServletSupport;
import net.shibboleth.shared.xml.SerializeSupport;

import jakarta.servlet.http.HttpServletResponse;

/**
 * SAML 2.0 HTTP Post binding message encoder.
 */
public class HTTPPostEncoder extends BaseSAML2MessageEncoder implements HTMLMessageEncoder {
    
    /** Default template ID. */
    @Nonnull @NotEmpty public static final String DEFAULT_TEMPLATE_ID = "/templates/saml2-post-binding.vm";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPPostEncoder.class);

    /** Velocity engine used to evaluate the template when performing POST encoding. */
    @NonnullAfterInit private VelocityEngine velocityEngine;

    /** ID of the Velocity template used when performing POST encoding. */
    @Nonnull private String velocityTemplateId;
    
    /** Digester for CSP hashes. */
    @Nullable private StringDigester cspDigester;

    /** Generator for CSP nonces. */
    @Nullable private IdentifierGenerationStrategy cspNonceGenerator;
    
    /** Constructor. */
    public HTTPPostEncoder() {
        velocityTemplateId = DEFAULT_TEMPLATE_ID;
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
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
    @Nonnull @NotEmpty public String getVelocityTemplateId() {
        return velocityTemplateId;
    }

    /**
     * Set the Velocity template id.
     * 
     * <p>Defaults to {@link #DEFAULT_TEMPLATE_ID}.</p>
     * 
     * @param newVelocityTemplateId the new Velocity template id
     */
    public void setVelocityTemplateId(@Nonnull @NotEmpty final String newVelocityTemplateId) {
        checkSetterPreconditions();
        velocityTemplateId = Constraint.isNotNull(StringSupport.trimOrNull(newVelocityTemplateId),
                "Velocity template ID cannot be null or empty");
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
    }

    /** {@inheritDoc} */
    protected void doEncode() throws MessageEncodingException {
        final MessageContext messageContext = getMessageContext();

        final Object outboundMessage = messageContext.getMessage();
        if (outboundMessage == null || !(outboundMessage instanceof SAMLObject)) {
            throw new MessageEncodingException("No outbound SAML message contained in message context");
        }
        
        final String endpointURL = getEndpointURL(messageContext).toString();
        assert endpointURL != null;

        postEncode(messageContext, endpointURL);
    }

    /**
     * Base64 and POST encodes the outbound message and writes it to the outbound transport.
     * 
     * @param messageContext current message context
     * @param endpointURL endpoint URL to which to encode message
     * 
     * @throws MessageEncodingException thrown if there is a problem encoding the message
     */
    protected void postEncode(@Nonnull final MessageContext messageContext, @Nonnull final String endpointURL) 
            throws MessageEncodingException {
        log.debug("Invoking Velocity template to create POST body");
        try {
            final VelocityContext context = new VelocityContext();

            populateVelocityContext(context, messageContext, endpointURL);

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
        } catch (final Exception e) {
            log.error("Error invoking Velocity template: {}", e.getMessage());
            throw new MessageEncodingException("Error creating output document", e);
        }
    }

    /**
     * Populate the Velocity context instance which will be used to render the POST body.
     * 
     * @param velocityContext the Velocity context instance to populate with data
     * @param messageContext the SAML message context source of data
     * @param endpointURL endpoint URL to which to encode message
     * @throws MessageEncodingException thrown if there is a problem encoding the message
     */
    protected void populateVelocityContext(@Nonnull final VelocityContext velocityContext,
            @Nonnull final MessageContext messageContext, @Nonnull final String endpointURL)
                    throws MessageEncodingException {

        final String encodedEndpointURL = HTMLEncoder.encodeForHTMLAttribute(endpointURL);
        log.debug("Encoding action url of '{}' with encoded value '{}'", endpointURL, encodedEndpointURL);
        velocityContext.put("action", encodedEndpointURL);
        velocityContext.put("binding", getBindingURI());
        
        if (cspDigester != null) {
            log.trace("Adding CSP digester to context");
            velocityContext.put("cspDigester", cspDigester);
        }
        if (cspNonceGenerator != null) {
            log.trace("Adding CSP nonce generator to context");
            velocityContext.put("cspNonce", cspNonceGenerator);
        }
        
        final SAMLObject outboundMessage = (SAMLObject) messageContext.getMessage();
        // Checked above.
        assert outboundMessage != null;
        
        log.debug("Marshalling and Base64 encoding SAML message");
        final Element domMessage = marshallMessage(outboundMessage);
        
        try {
            final String messageXML = SerializeSupport.nodeToString(domMessage);
            final String encodedMessage = Base64.getEncoder().encodeToString(messageXML.getBytes("UTF-8"));
            if (outboundMessage instanceof RequestAbstractType) {
                velocityContext.put("SAMLRequest", encodedMessage);
            } else if (outboundMessage instanceof StatusResponseType) {
                velocityContext.put("SAMLResponse", encodedMessage);
            } else {
                throw new MessageEncodingException(
                        "SAML message is neither a SAML RequestAbstractType or StatusResponseType");
            }
        } catch (final UnsupportedEncodingException e) {
            log.error("UTF-8 encoding is not supported, this VM is not Java compliant");
            throw new MessageEncodingException("Unable to encode message, UTF-8 encoding is not supported");
        }

        final String relayState = SAMLBindingSupport.getRelayState(messageContext);
        if (SAMLBindingSupport.checkRelayState(relayState)) {
            final String encodedRelayState = HTMLEncoder.encodeForHTMLAttribute(relayState);
            log.debug("Setting RelayState parameter to: '{}', encoded as '{}'", relayState, encodedRelayState);
            velocityContext.put("RelayState", encodedRelayState);
        }
    }

}