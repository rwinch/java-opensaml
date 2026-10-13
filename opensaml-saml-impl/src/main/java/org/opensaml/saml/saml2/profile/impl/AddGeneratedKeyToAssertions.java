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

package org.opensaml.saml.saml2.profile.impl;

import java.util.Base64;
import java.util.function.Function;

import javax.annotation.Nonnull;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.action.AbstractConditionalProfileAction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.OutboundMessageContextLookup;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.messaging.context.ECPContext;
import org.opensaml.saml.ext.samlec.GeneratedKey;
import org.opensaml.saml.saml2.core.Advice;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.profile.SAML2ActionSupport;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.constraint.NonnullBeforeExec;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * Action to add a {@link GeneratedKey} extension to every {@link Assertion} in a {@link Response} message.
 * 
 * <p>If the containing {@link Advice} is not present, it will be created.</p>
 * 
 * <p>The {@link ECPContext} to read from is located via lookup strategy, by default beneath the
 * outbound message context.</p>
 * 
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_MSG_CTX}
 * @event {@link EventIds#MESSAGE_PROC_ERROR}
 */
public class AddGeneratedKeyToAssertions extends AbstractConditionalProfileAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AddGeneratedKeyToAssertions.class);

    /** Strategy used to locate the {@link ECPContext} to operate on. */
    @Nonnull private Function<ProfileRequestContext,ECPContext> ecpContextLookupStrategy;
    
    /** Strategy used to locate the {@link Response} to operate on. */
    @Nonnull private Function<ProfileRequestContext,Response> responseLookupStrategy;

    /** ECPContext to read from. */
    @NonnullBeforeExec private ECPContext ecpContext;
    
    /** Response to modify. */
    @NonnullBeforeExec private Response response;

    /** Constructor. */
    public AddGeneratedKeyToAssertions() {
        ecpContextLookupStrategy =
                new ChildContextLookup<>(ECPContext.class).compose(
                        new OutboundMessageContextLookup());
        responseLookupStrategy = new MessageLookup<>(Response.class).compose(
                new OutboundMessageContextLookup());
    }

    /**
     * Set the strategy used to locate the {@link ECPContext} to operate on.
     * 
     * @param strategy lookup strategy
     */
    public void setECPContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext,ECPContext> strategy) {
        checkSetterPreconditions();

        ecpContextLookupStrategy = Constraint.isNotNull(strategy, "ECPContext lookup strategy cannot be null");
    }
    
    /**
     * Set the strategy used to locate the {@link Response} to operate on.
     * 
     * @param strategy lookup strategy
     */
    public void setResponseLookupStrategy(@Nonnull final Function<ProfileRequestContext,Response> strategy) {
        checkSetterPreconditions();

        responseLookupStrategy = Constraint.isNotNull(strategy, "Response lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        
        ecpContext = ecpContextLookupStrategy.apply(profileRequestContext);
        if (ecpContext == null || ecpContext.getSessionKey() == null) {
            log.debug("{} No session key to add, nothing to do", getLogPrefix());
            return false;
        }
        
        log.debug("{} Attempting to add GeneratedKey to every Assertion in Response", getLogPrefix());

        response = responseLookupStrategy.apply(profileRequestContext);
        if (response == null) {
            log.debug("{} No SAML response located in current profile request context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        } else if (response.getAssertions().isEmpty()) {
            log.debug("{} No assertions in response message, nothing to do", getLogPrefix());
            return false;
        }
        
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        final SAMLObjectBuilder<GeneratedKey> keyBuilder = (SAMLObjectBuilder<GeneratedKey>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<GeneratedKey>ensureBuilder(
                        GeneratedKey.DEFAULT_ELEMENT_NAME);

        final byte[] keyBytes = ecpContext.getSessionKey();
        // Checked above.
        assert keyBytes != null;
        final String key = Base64.getEncoder().encodeToString(keyBytes);
        
        for (final Assertion assertion : response.getAssertions()) {
            assert assertion != null;
            final Advice advice = SAML2ActionSupport.addAdviceToAssertion(this, assertion);
            final GeneratedKey gk = keyBuilder.buildObject();
            gk.setValue(key);
            advice.getChildren().add(gk);
        }        
        log.debug("{} Added GeneratedKey to Advice", getLogPrefix());
    }

}