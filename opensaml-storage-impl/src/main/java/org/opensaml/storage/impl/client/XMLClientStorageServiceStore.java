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

package org.opensaml.storage.impl.client;

import java.io.IOException;
import java.io.StringReader;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.storage.MutableStorageRecord;
import org.opensaml.storage.impl.client.ClientStorageService.ClientStorageSource;
import org.slf4j.Logger;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.base.Strings;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.security.DataSealerException;
import net.shibboleth.shared.xml.ElementSupport;
import net.shibboleth.shared.xml.ParserPool;
import net.shibboleth.shared.xml.SerializeSupport;
import net.shibboleth.shared.xml.XMLParserException;
import net.shibboleth.shared.xml.impl.BasicParserPool;

/**
 * XML-based storage for {@link ClientStorageService}.
 */
public class XMLClientStorageServiceStore extends AbstractClientStorageServiceStore {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(XMLClientStorageServiceStore.class);
    
    /** Parser machinery. */
    @Nonnull private final ParserPool parserPool;

    /**
     * Constructor.
     * 
     * @param pool {@link ParserPool} to use
     */
    public XMLClientStorageServiceStore(@Nonnull final ParserPool pool) {
        parserPool = Constraint.isNotNull(pool, "ParserPool cannot be null");
    }

    //Checkstyle: CyclomaticComplexity|MethodLength OFF
    /** {@inheritDoc} */
    public void doLoad(@Nullable @NotEmpty final String raw) throws IOException {
        try {
            final Document doc = parserPool.parse(new StringReader(raw));
            final Element rootElement = doc != null ? doc.getDocumentElement() : null;
            
            if (rootElement == null || !"map".equals(rootElement.getNodeName())) {
                throw new IOException("Found invalid data structure while parsing context map");
            }
            
            Element contextElement = ElementSupport.getFirstChildElement(rootElement);
            while (contextElement != null && "c".equals(contextElement.getNodeName())) {

                final String contextId = contextElement.getAttribute("id");
                if (!Strings.isNullOrEmpty(contextId)) {
                    // Create new context if necessary.
                    Map<String,MutableStorageRecord<?>> dataMap = getContextMap().get(contextId);
                    if (dataMap == null) {
                        dataMap = new HashMap<>();
                        getContextMap().put(contextId, dataMap);
                    }
                    
                    Element keyElement = ElementSupport.getFirstChildElement(contextElement);
                    while (keyElement != null && "k".equals(keyElement.getNodeName())) {
                        final String keyId = keyElement.getAttribute("id");
                        if (!Strings.isNullOrEmpty(keyId)) {
                            
                            Long exp = null;
                            if (keyElement.hasAttribute("x")) {
                                exp = Long.valueOf(keyElement.getAttribute("x"));
                            }
                            
                            dataMap.put(keyId, new MutableStorageRecord<>(keyElement.getTextContent(), exp));
                        }
                        
                        keyElement = ElementSupport.getNextSiblingElement(keyElement);
                    }
                }
                
                contextElement = ElementSupport.getNextSiblingElement(contextElement);
            }
            setDirty(false);
        } catch (final XMLParserException e) {
            log.error("Found invalid data structure while parsing context map", e);
            throw new IOException(e);
        }
    }

    /** {@inheritDoc} */
    @Nullable public ClientStorageServiceOperation save(@Nonnull final ClientStorageService storageService)
            throws IOException {
        
        if (!isDirty()) {
            log.trace("{} Storage state has not been modified, save operation skipped", storageService.getLogPrefix());
            return null;
        }
        
        final ClientStorageSource source = getSource();
        if (source == null) {
            throw new IOException("Client storage medium not set");
        }
        
        if (getContextMap().isEmpty()) {
            log.trace("{} Data is empty", storageService.getLogPrefix());
            setDirty(false);
            return new ClientStorageServiceOperation(storageService.ensureId(), storageService.getStorageName(), null,
                    source);
        }

        long exp = 0L;
        final long now = System.currentTimeMillis();
        boolean empty = true;

        try {
            final Document doc = parserPool.newDocument();
            final Element rootElement = doc.createElement("map");
            
            for (final Map.Entry<String,Map<String,MutableStorageRecord<?>>> context : getContextMap().entrySet()) {
                if (!context.getValue().isEmpty()) {
                    final Element contextElement = doc.createElement("c");
                    contextElement.setAttribute("id", context.getKey());
                    
                    for (final Map.Entry<String,MutableStorageRecord<?>> entry : context.getValue().entrySet()) {
                        final MutableStorageRecord<?> record = entry.getValue();
                        final Long recexp = record.getExpiration();
                        if (recexp == null || recexp > now) {
                            empty = false;
                            final Element keyElement = doc.createElement("k");
                            keyElement.setAttribute("id", entry.getKey());
                            keyElement.setTextContent(record.getValue());
                            
                            if (recexp != null) {
                                keyElement.setAttribute("x", recexp.toString());
                                exp = Math.max(exp, recexp);
                            }
                            contextElement.appendChild(keyElement);
                        }
                    }
                    
                    rootElement.appendChild(contextElement);
                }
            }

            if (empty) {
                log.trace("{} Data is empty", storageService.getLogPrefix());
                setDirty(false);
                return new ClientStorageServiceOperation(storageService.ensureId(), storageService.getStorageName(),
                        null, source);
            }
            
            assert rootElement != null;
            final String raw = SerializeSupport.nodeToString(rootElement);
            
            log.trace("{} Size of data before encryption is {}", storageService.getLogPrefix(), raw.length());
            log.trace("{} Data before encryption is {}", storageService.getLogPrefix(), raw);
            try {
                final String wrapped = storageService.getDataSealer().wrap(raw,
                        exp > 0 ? Instant.ofEpochMilli(exp) : Instant.now().plus(Duration.ofDays(1)));
                log.trace("{} Size of data after encryption is {}", storageService.getLogPrefix(), wrapped.length());
                setDirty(false);
                return new ClientStorageServiceOperation(storageService.ensureId(), storageService.getStorageName(),
                        wrapped, source);
            } catch (final DataSealerException e) {
                throw new IOException(e);
            }
        } catch (final XMLParserException e) {
            throw new IOException(e);
        }
    }
//Checkstyle: CyclomaticComplexity|MethodLength ON
    
    /** Factory for XML-backed store. */
    public static class XMLClientStorageServiceStoreFactory extends AbstractInitializableComponent implements Factory {

        /** ParserPool to pass into stores. */
        @Nonnull private final ParserPool parserPool;
        
        /** Constructor. */
        public XMLClientStorageServiceStoreFactory() {
            parserPool = new BasicParserPool();
        }
        
        /** {@inheritDoc} */
        @Override
        protected void doInitialize() throws ComponentInitializationException {
            super.doInitialize();
            
            ((BasicParserPool) parserPool).setNamespaceAware(false);
            ((BasicParserPool) parserPool).initialize();
        }
        
        /** {@inheritDoc} */
        @Nonnull public ClientStorageServiceStore load(@Nullable @NotEmpty final String raw,
                @Nonnull final ClientStorageSource src) {
            final ClientStorageServiceStore store = new XMLClientStorageServiceStore(parserPool);
            store.load(raw, src);
            return store;
        }
    }

}