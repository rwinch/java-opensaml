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

package org.opensaml.saml.saml2.binding.security.impl;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.annotation.Nonnull;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.binding.security.impl.BaseSAMLSimpleSignatureSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCriterion;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.google.common.base.Strings;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.xml.ParserPool;
import net.shibboleth.shared.xml.XMLParserException;

/**
 * Message handler which evaluates simple "blob" signatures according to the SAML 2 HTTP-POST-SimpleSign binding.
 */
public class SAML2HTTPPostSimpleSignSecurityHandler extends BaseSAMLSimpleSignatureSecurityHandler {

    /** Logger. */
    @Nonnull private Logger log = LoggerFactory.getLogger(SAML2HTTPPostSimpleSignSecurityHandler.class);

    /** Parser pool to use to process KeyInfo request parameter. */
    @NonnullAfterInit private ParserPool parserPool;

    /** KeyInfo resolver to use to process KeyInfo request parameter. */
    @NonnullAfterInit private KeyInfoCredentialResolver keyInfoResolver;
    
    /**
     * Get the parser pool.
     * 
     * @return Returns the parser pool.
     */
    @NonnullAfterInit public ParserPool getParserPool() {
        return parserPool;
    }

    /**
     * Set the parser pool.
     * 
     * @param newParserPool The parser to set.
     */
    public void setParser(@Nonnull final ParserPool newParserPool) {
        checkSetterPreconditions();
        parserPool = Constraint.isNotNull(newParserPool, "ParserPool cannot be null");
    }

    /**
     * Get the KeyInfo credential resolver.
     * 
     * @return Returns the keyInfoResolver.
     */
    @NonnullAfterInit public KeyInfoCredentialResolver getKeyInfoResolver() {
        return keyInfoResolver;
    }

    /**
     * Set the KeyInfo credential resolver.
     * 
     * @param newKeyInfoResolver The keyInfoResolver to set.
     */
    public void setKeyInfoResolver(@Nonnull final KeyInfoCredentialResolver newKeyInfoResolver) {
        checkSetterPreconditions();
        keyInfoResolver = Constraint.isNotNull(newKeyInfoResolver, "KeyInfoCredentialResolver cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        Constraint.isNotNull(parserPool, "ParserPool cannot be null");
        Constraint.isNotNull(keyInfoResolver, "KeyInfoCredentialResolver cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean ruleHandles(@Nonnull final MessageContext messageContext) {
        return "POST".equals(getHttpServletRequest().getMethod())
                && SAMLConstants.SAML2_POST_SIMPLE_SIGN_BINDING_URI.equals(
                        messageContext.ensureSubcontext(SAMLBindingContext.class).getBindingUri());
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull @Unmodifiable @NotLive protected List<Credential> getRequestCredentials(
            @Nonnull final MessageContext samlContext)
            throws MessageHandlerException {

        final String kiBase64 = getHttpServletRequest().getParameter("KeyInfo");
        if (Strings.isNullOrEmpty(kiBase64)) {
            log.debug("Form control data did not contain a KeyInfo");
            return CollectionSupport.emptyList();
        }
        log.debug("Found a KeyInfo in form control data, extracting validation credentials");

        final Unmarshaller unmarshaller =
                XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(KeyInfo.DEFAULT_ELEMENT_NAME);
        if (unmarshaller == null) {
            throw new MessageHandlerException("Could not obtain a KeyInfo unmarshaller");
        }

        ByteArrayInputStream is = null;
        try {
            is = new ByteArrayInputStream(Base64.getMimeDecoder().decode(kiBase64));
        } catch (final IllegalArgumentException e) {
            log.warn("Error base64 decoding KeyInfo data: {}", e.getMessage());
            throw new MessageHandlerException("Error base64 decoding KeyInfo data", e);
        }
        KeyInfo keyInfo = null;
        try {
            final Document doc = getParserPool().parse(is);
            keyInfo = (KeyInfo) unmarshaller.unmarshall(doc.getDocumentElement());
        } catch (final XMLParserException e) {
            log.warn("Error parsing KeyInfo data: {}", e.getMessage());
            throw new MessageHandlerException("Error parsing KeyInfo data", e);
        } catch (final UnmarshallingException e) {
            log.warn("Error unmarshalling KeyInfo data: {}", e.getMessage());
            throw new MessageHandlerException("Error unmarshalling KeyInfo data", e);
        }

        final List<Credential> credentials = new ArrayList<>();
        final CriteriaSet criteriaSet = new CriteriaSet(new KeyInfoCriterion(keyInfo));
        try {
            for (final Credential cred : keyInfoResolver.resolve(criteriaSet)) {
                credentials.add(cred);
            }
        } catch (final ResolverException e) {
            log.warn("Error resolving credentials from KeyInfo: {}", e.getMessage());
            throw new MessageHandlerException("Error resolving credentials from KeyInfo", e);
        }

        return credentials;
    }

}