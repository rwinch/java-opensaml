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

package org.opensaml.spring.trust;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.util.KeyPairUtil;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.trust.impl.ExplicitKeyTrustEngine;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Support;
import org.slf4j.Logger;

import org.springframework.beans.FatalBeanException;

import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.primitive.AnnotationsSupport;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.resource.Resource;
import net.shibboleth.shared.spring.factory.AbstractComponentAwareFactoryBean;

/**
 * Factory bean for simple use cases involving the {@link ExplicitKeyTrustEngine} and static credentials.
 *
 * TODO: Remove the {@link #destroyInstance()} from this class in V6.
 *
 * @since 3.3.0
 */
public class StaticExplicitKeyFactoryBean extends AbstractComponentAwareFactoryBean<ExplicitKeyTrustEngine> {

    /** Class logger. */
    @Nonnull private Logger log = LoggerFactory.getLogger(StaticExplicitKeyFactoryBean.class);

    /** The resources to be turned into keys. */
    @Nonnull private List<Resource> keyResources;

    /** The resources to be turned into certificates. */
    @Nonnull private List<Resource> certificateResources;

    /** Constructor. */
    public StaticExplicitKeyFactoryBean() {
        keyResources = CollectionSupport.emptyList();
        certificateResources = CollectionSupport.emptyList();
    }
    
    /**
     * Set the resources which we will convert into certificates.
     * 
     * @param keys the resources
     */
    public void setPublicKeys(@Nullable final List<Resource> keys) {
        keyResources = keys != null ? keys : CollectionSupport.emptyList();
    }
    
    /**
     * Set the resources which we will convert into certificates.
     * 
     * @param certs the resources
     */
    public void setCertificates(@Nullable final List<Resource> certs) {
        certificateResources = certs != null ? certs : CollectionSupport.emptyList();
    }

    /**
     * Get the configured certificates.
     * 
     * @return the certificates null
     */
    @Nonnull protected List<Credential> getCredentials() {
        
        final List<Credential> credentials = new ArrayList<>(keyResources.size() + certificateResources.size());

        for (final Resource f : keyResources) {
            try(final InputStream is = f.getInputStream()) {
                credentials.add(new BasicCredential(KeyPairUtil.readPublicKey(is)));
            } catch (final EncodingException|StreamException|IOException e) {
                log.error("Could not decode public key from {}: {}", f.getDescription(), e.getMessage());
                throw new FatalBeanException("Could not decode public key from " + f.getDescription(), e);
            }
        }
                
        for (final Resource f : certificateResources) {
            try(final InputStream is = f.getInputStream()) {
                final Collection<X509Certificate> raw = X509Support.decodeCertificates(is);
                if (raw != null) {
                    raw.forEach(x -> {
                        if (x != null) {
                            credentials.add(new BasicX509Credential(x));
                            }
                        }
                    );
                }
                
            } catch (final CertificateException | IOException e) {
                log.error("Could not decode certificate from {}: {}", f.getDescription(), e.getMessage());
                throw new FatalBeanException("Could not decode certificate from " + f.getDescription(), e);
            }
        }

        return credentials;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull  public Class<?> getObjectType() {
        return ExplicitKeyTrustEngine.class;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected ExplicitKeyTrustEngine doCreateInstance() throws Exception {
        return new ExplicitKeyTrustEngine(new StaticCredentialResolver(getCredentials()));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Call a destroy method if aposite.</p>
     * <p> We do not call the parent tear down so as to avoid any deprecation logging</>
     */
    @Override protected void destroyInstance(@Nullable final ExplicitKeyTrustEngine instance) throws Exception {
        AnnotationsSupport.callOnTeardownAnnotations(instance);
    }
}
