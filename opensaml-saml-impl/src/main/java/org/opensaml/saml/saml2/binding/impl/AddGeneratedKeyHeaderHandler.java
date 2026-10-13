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

package org.opensaml.saml.saml2.binding.impl;

import java.util.Base64;

import javax.annotation.Nonnull;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.AbstractMessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.messaging.context.ECPContext;
import org.opensaml.saml.ext.samlec.GeneratedKey;
import org.opensaml.soap.messaging.SOAPMessagingSupport;
import org.opensaml.soap.soap11.ActorBearing;
import org.opensaml.soap.util.SOAPSupport;

import net.shibboleth.shared.annotation.constraint.NonnullBeforeExec;

/**
 * MessageHandler to add the ECP {@link GeneratedKey} header to an outgoing SOAP envelope.
 */
public class AddGeneratedKeyHeaderHandler extends AbstractMessageHandler {

    /** Session key to encode and include. */
    @NonnullBeforeExec private byte[] sessionKey; 
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {
        
        if (!super.doPreInvoke(messageContext)) {
            return false;
        }

        final ECPContext ctx = messageContext.getSubcontext(ECPContext.class);
        sessionKey = ctx != null ? ctx.getSessionKey() : null;
        if (sessionKey == null) {
            return false;
        }
        
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {
        final SAMLObjectBuilder<GeneratedKey> builder = (SAMLObjectBuilder<GeneratedKey>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<GeneratedKey>ensureBuilder(
                        GeneratedKey.DEFAULT_ELEMENT_NAME);
        try {
            final GeneratedKey header = builder.buildObject();
            assert sessionKey != null;
            header.setValue(Base64.getEncoder().encodeToString(sessionKey));
            SOAPSupport.addSOAP11ActorAttribute(header, ActorBearing.SOAP11_ACTOR_NEXT);      
            SOAPMessagingSupport.addHeaderBlock(messageContext, header);
        } catch (final Exception e) {
            throw new MessageHandlerException(e);
        }
    }
    
}