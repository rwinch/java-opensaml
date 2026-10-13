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

package org.opensaml.saml.common.binding.security.impl;

import java.util.Base64;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.AbstractHttpServletRequestMessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.saml2.binding.decoding.impl.SimpleSignatureContext;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.SignatureValidationParametersCriterion;
import org.slf4j.Logger;

import com.google.common.base.Strings;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.resolver.CriteriaSet;

/**
 * Base class for security-oriented message handlers which verify simple "blob" signatures computed 
 * over some components of a request.
 */
public abstract class BaseSAMLSimpleSignatureSecurityHandler extends AbstractHttpServletRequestMessageHandler {

    /** Logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BaseSAMLSimpleSignatureSecurityHandler.class);
    
    /** The context representing the SAML peer entity. */
    @Nullable private SAMLPeerEntityContext peerContext;
    
    /** The SAML protocol in use. */
    @Nullable private String samlProtocol;
    
    /** The SAML role in use. */
    @Nullable private QName samlRole;

    /** Parameters for signature validation. */
    @Nullable private SignatureValidationParameters signatureValidationParameters;
    
    /** Signature trust engine used to validate raw signatures. */
    @Nullable private SignatureTrustEngine trustEngine;

    /**
     * Gets the engine used to validate the signature.
     * 
     * @return engine engine used to validate the signature
     */
    @Nullable protected SignatureTrustEngine getTrustEngine() {
        return trustEngine;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {
        
        if (!super.doPreInvoke(messageContext)) {
            return false;
        }
        
        peerContext = messageContext.getSubcontext(SAMLPeerEntityContext.class);
        samlRole = peerContext != null ? peerContext.getRole() : null;
        if (samlRole == null) {
            throw new MessageHandlerException("SAMLPeerEntityContext was missing or unpopulated");
        }
        
        final SAMLProtocolContext samlProtocolContext = messageContext.getSubcontext(SAMLProtocolContext.class);
        samlProtocol = samlProtocolContext != null ? samlProtocolContext.getProtocol() : null;
        if (samlProtocol == null) {
            throw new MessageHandlerException("SAMLProtocolContext was missing or unpopulated");
        }
        
        final SecurityParametersContext secParams = messageContext.getSubcontext(SecurityParametersContext.class);
        signatureValidationParameters = secParams != null ? secParams.getSignatureValidationParameters() : null;
        trustEngine = signatureValidationParameters != null
                ? signatureValidationParameters.getSignatureTrustEngine() : null;
        if (trustEngine == null) {
            throw new MessageHandlerException("No SignatureTrustEngine was available from the MessageContext");
        }
        
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {
        log.debug("{} Evaluating simple signature rule of type: {}", getLogPrefix(), getClass().getName());

        if (!ruleHandles(messageContext)) {
            log.debug("{} Handler can not handle this request, skipping", getLogPrefix());
            return;
        }

        final byte[] signature = getSignature();
        if (signature == null || signature.length == 0) {
            log.debug("{} HTTP request was not signed via simple signature mechanism, skipping", getLogPrefix());
            return;
        }

        final String sigAlg = getSignatureAlgorithm();
        if (Strings.isNullOrEmpty(sigAlg)) {
            log.warn("{} Signature algorithm could not be extracted from request, cannot validate simple signature",
                    getLogPrefix());
            return;
        }
        assert sigAlg != null;

        final byte[] signedContent = getSignedContent(messageContext);
        if (signedContent == null || signedContent.length == 0) {
            log.warn("{} Signed content could not be extracted from HTTP request, cannot validate", getLogPrefix());
            return;
        }

        doEvaluate(signature, signedContent, sigAlg, messageContext);
    }

    /**
     * Evaluate the simple signature based on information in the request and/or message context.
     * 
     * @param signature the signature value
     * @param signedContent the content that was signed
     * @param algorithmURI the signature algorithm URI which was used to sign the content
     * @param messageContext the SAML message context being processed
     * @throws MessageHandlerException thrown if there are errors during the signature validation process
     * 
     */
    private void doEvaluate(@Nonnull @NotEmpty final byte[] signature, @Nonnull @NotEmpty final byte[] signedContent,
            @Nonnull @NotEmpty final String algorithmURI, @Nonnull final MessageContext messageContext)
                    throws MessageHandlerException {

        final List<Credential> candidateCredentials = getRequestCredentials(messageContext);

        final SAMLPeerEntityContext peerEntityContext = peerContext;
        assert peerEntityContext != null;
        final String contextEntityID = peerEntityContext.getEntityId();
        
        //TODO authentication flags - on peer or on message?
        
        if (contextEntityID != null) {
            log.debug("{} Attempting to validate SAML protocol message simple signature using context entityID: {}",
                    getLogPrefix(), contextEntityID);
            final CriteriaSet criteriaSet = buildCriteriaSet(contextEntityID, messageContext);
            if (validateSignature(signature, signedContent, algorithmURI, criteriaSet, candidateCredentials)) {
                log.debug("{} Validation of request simple signature succeeded", getLogPrefix());
                if (!peerEntityContext.isAuthenticated()) {
                    log.debug(
                            "{} Authentication via request simple signature succeeded for context issuer entity ID {}",
                            getLogPrefix(), contextEntityID);
                    peerEntityContext.setAuthenticated(true);
                }
                return;
            }
            log.warn("{} Validation of request simple signature failed for context issuer: {}", getLogPrefix(),
                    contextEntityID);
            throw new MessageHandlerException("Validation of request simple signature failed for context issuer");
        }
            
        final String derivedEntityID = deriveSignerEntityID(messageContext);
        if (derivedEntityID != null) {
            log.debug("{} Attempting to validate SAML protocol message simple signature using derived entityID: {}",
                    getLogPrefix(), derivedEntityID);
            final CriteriaSet criteriaSet = buildCriteriaSet(derivedEntityID, messageContext);
            if (validateSignature(signature, signedContent, algorithmURI, criteriaSet, candidateCredentials)) {
                log.debug("{} Validation of request simple signature succeeded", getLogPrefix());
                if (!peerEntityContext.isAuthenticated()) {
                    log.debug("{} Authentication via request simple signature succeeded for derived issuer {}",
                            getLogPrefix(), derivedEntityID);
                    peerEntityContext.setEntityId(derivedEntityID);
                    peerEntityContext.setAuthenticated(true);
                }
                return;
            }
            log.warn("{} Validation of request simple signature failed for derived issuer: {}", getLogPrefix(),
                    derivedEntityID);
            throw new MessageHandlerException("Validation of request simple signature failed for derived issuer");
        }
        
        log.warn("{} Neither context nor derived issuer available, cannot attempt SAML simple signature validation",
                getLogPrefix());
        throw new MessageHandlerException("No message issuer available, cannot attempt simple signature validation");
    }

    /**
     * Validate the simple signature.
     * 
     * @param signature the signature value
     * @param signedContent the content that was signed
     * @param algorithmURI the signature algorithm URI which was used to sign the content
     * @param criteriaSet criteria used to describe and/or resolve the information which serves as the basis for trust
     *            evaluation
     * @param candidateCredentials the request-derived candidate credential(s) containing the validation key for the
     *            signature (optional)
     * @return true if signature can be verified successfully, false otherwise
     * 
     * @throws MessageHandlerException thrown if there are errors during the signature validation process
     * 
     */
    protected boolean validateSignature(@Nonnull @NotEmpty final byte[] signature,
            @Nonnull @NotEmpty final byte[] signedContent, @Nonnull @NotEmpty final String algorithmURI,
            @Nonnull final CriteriaSet criteriaSet,
            @Nonnull final List<Credential> candidateCredentials) throws MessageHandlerException {

        final SignatureTrustEngine engine = getTrustEngine();
        assert engine != null;

        // Some bindings allow candidate signing credentials to be supplied (e.g. via ds:KeyInfo), some do not.
        // So have 2 slightly different cases.
        try {
            if (candidateCredentials == null || candidateCredentials.isEmpty()) {
                if (engine.validate(signature, signedContent, algorithmURI, criteriaSet, null)) {
                    log.debug("{} Simple signature validation (with no request-derived credentials) was successful",
                            getLogPrefix());
                    return true;
                }
                log.warn("{} Simple signature validation (with no request-derived credentials) failed",
                        getLogPrefix());
                return false;
            }
            for (final Credential cred : candidateCredentials) {
                if (engine.validate(signature, signedContent, algorithmURI, criteriaSet, cred)) {
                    log.debug("{} Simple signature validation succeeded with a request-derived credential",
                            getLogPrefix());
                    return true;
                }
            }
            log.warn("{} Signature validation using request-derived credentials failed", getLogPrefix());
            return false;
        } catch (final SecurityException e) {
            log.warn("{} Error evaluating the request's simple signature using the trust engine: {}", getLogPrefix(),
                    e.getMessage());
            throw new MessageHandlerException("Error during trust engine evaluation of the simple signature", e);
        }
    }

    /**
     * Extract any candidate validation credentials from the request and/or message context.
     * 
     * Some bindings allow validataion keys for the simple signature to be supplied, and others do not.
     * @param messageContext the SAML message context being processed
     * 
     * @return a list of candidate validation credentials in the request, or null if none were present
     * @throws MessageHandlerException thrown if there is an error during request processing
     */
    @Nonnull @Unmodifiable @NotLive protected List<Credential> getRequestCredentials(
            @Nonnull final MessageContext messageContext)
            throws MessageHandlerException {
        // This will be specific to the binding and message types, so no default.
        return CollectionSupport.emptyList();
    }

    /**
     * Extract the signature value from the request, in the form suitable for input into
     * {@link SignatureTrustEngine#validate(byte[], byte[], String, CriteriaSet, Credential)}.
     * 
     * Defaults to the Base64-decoded value of the HTTP request parameter named <code>Signature</code>.
     * 
     * @return the signature value
     * @throws MessageHandlerException thrown if there is an error during request processing
     */
    @Nullable protected byte[] getSignature() throws MessageHandlerException {
        final String signature = getHttpServletRequest().getParameter("Signature");
        if (Strings.isNullOrEmpty(signature)) {
            return null;
        }
        assert signature != null;
        try {
            return Base64.getMimeDecoder().decode(signature);
        } catch (final IllegalArgumentException e) {
           throw new MessageHandlerException("Signature could not be base64 decoded",e);
        }
    }

    /**
     * Extract the signature algorithm URI value from the request.
     * 
     * Defaults to the HTTP request parameter named <code>SigAlg</code>.
     * 
     * @return the signature algorithm URI value
     * @throws MessageHandlerException thrown if there is an error during request processing
     */
    @Nullable protected String getSignatureAlgorithm()
            throws MessageHandlerException {
        return getHttpServletRequest().getParameter("SigAlg");
    }

    /**
     * Derive the signer's entity ID from the message context.
     * 
     * This is implementation-specific and there is no default. This is primarily an extension point for subclasses.
     * 
     * @param messageContext the SAML message context being processed
     * @return the signer's derived entity ID
     * @throws MessageHandlerException thrown if there is an error during request processing
     */
    @Nullable protected String deriveSignerEntityID(@Nonnull final MessageContext messageContext)
            throws MessageHandlerException {
        // No default
        return null;
    }

    /**
     * Build a criteria set suitable for input to the trust engine.
     * 
     * @param entityID the candidate issuer entity ID which is being evaluated
     * @param messageContext the message context which is being evaluated
     * @return a newly constructly set of criteria suitable for the configured trust engine
     * @throws MessageHandlerException thrown if criteria set can not be constructed
     */
    @Nonnull protected CriteriaSet buildCriteriaSet(@Nullable final String entityID,
            @Nonnull final MessageContext messageContext) throws MessageHandlerException {

        final CriteriaSet criteriaSet = new CriteriaSet();
        if (!Strings.isNullOrEmpty(entityID)) {
            assert entityID != null;
            criteriaSet.add(new EntityIdCriterion(entityID));
        }
        
        assert samlRole != null;
        criteriaSet.add(new EntityRoleCriterion(samlRole));
        assert samlProtocol != null;
        criteriaSet.add(new ProtocolCriterion(samlProtocol));
        criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
        
        if (signatureValidationParameters != null) {
            criteriaSet.add(new SignatureValidationParametersCriterion(signatureValidationParameters));
        }

        return criteriaSet;
    }

    /**
     * Get the content over which to validate the signature, in the form suitable for input into
     * {@link SignatureTrustEngine#validate(byte[], byte[], String, CriteriaSet, Credential)}.
     * 
     * @param messageContext the message context which is being evaluated
     * 
     * @return the signed content extracted from the request, in the format suitable for input to the trust engine.
     * @throws MessageHandlerException thrown if there is an error during request processing
     */
    @Nullable protected byte[] getSignedContent(@Nonnull final MessageContext messageContext)
            throws MessageHandlerException {
       
        return messageContext.ensureSubcontext(SimpleSignatureContext.class).getSignedContent();
    };

    /**
     * Determine whether the rule should handle the request, based on the unwrapped HTTP servlet request and/or message
     * context.
     * @param messageContext the SAML message context being processed
     * 
     * @return true if the rule should attempt to process the request, otherwise false
     * @throws MessageHandlerException thrown if there is an error during request processing
     */
    protected abstract boolean ruleHandles(@Nonnull final MessageContext messageContext)
            throws MessageHandlerException;

}