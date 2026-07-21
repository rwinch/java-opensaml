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
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.x509.PKIXTrustEvaluator;
import org.opensaml.security.x509.X509Support;
import org.opensaml.security.x509.impl.BasicPKIXValidationInformation;
import org.opensaml.security.x509.impl.BasicX509CredentialNameEvaluator;
import org.opensaml.security.x509.impl.CertPathPKIXTrustEvaluator;
import org.opensaml.security.x509.impl.CertPathPKIXValidationOptions;
import org.opensaml.security.x509.impl.PKIXX509CredentialTrustEngine;
import org.opensaml.security.x509.impl.StaticPKIXValidationInformationResolver;
import org.opensaml.security.x509.impl.X509CredentialNameEvaluator;
import org.slf4j.Logger;

import org.springframework.beans.FatalBeanException;

import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.primitive.AnnotationsSupport;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.resource.Resource;
import net.shibboleth.shared.spring.factory.AbstractComponentAwareFactoryBean;

/**
 * File system specific bean for PKIXX509CredentialTrustEngine.
 *
 * TODO: Remove the {@link #destroyInstance()} from this class in V6.
 *
 * @since 3.3.0
 */
public class StaticPKIXFactoryBean extends AbstractComponentAwareFactoryBean<PKIXX509CredentialTrustEngine> {

    /** log. */
    @Nonnull private Logger log = LoggerFactory.getLogger(StaticPKIXFactoryBean.class);

    /** Certificate resources. */
    @Nullable private List<Resource> certificateResources;

    /** CRL resources. */
    @Nullable private List<Resource> crlResources;

    /** Verification depth. */
    @Nullable private Integer verifyDepth;
    
    /** Explicit subject name(s) to match. */
    @Nullable private Set<String> trustedNames;
    
    /** Whether to enable name checking. If true a default implementation will be used.
     * See also: {@link #credentialNameEvaluator}. */
    private boolean checkNames;

    /** Custom instance of {@link PKIXTrustEvaluator} to use. */
    @Nullable private PKIXTrustEvaluator trustEvaluator;

    /** Custom instance of {@link X509CredentialNameEvaluator} to use.
     * A non-null value overrides {@link #checkNames}. */
    @Nullable private X509CredentialNameEvaluator credentialNameEvaluator;

    /** Constructor. */
    public StaticPKIXFactoryBean() {
        checkNames = true;
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull public Class<?> getObjectType() {
        return PKIXX509CredentialTrustEngine.class;
    }
    
    /**
     * Set the resources which we will convert into certificates.
     * 
     * @param certs the resources
     */
    public void setCertificates(@Nullable final List<Resource> certs) {
        certificateResources = certs;
    }

    /**
     * Set the resources which we will convert into CRLs.
     * 
     * @param crls the resources
     */
    public void setCRLs(@Nullable final List<Resource> crls) {
        crlResources = crls;
    }

    /**
     * Set the verify depth.
     * 
     * @param depth value to set
     */
    public void setVerifyDepth(@Nullable final Integer depth) {
        verifyDepth = depth;
    }

    /**
     * Set whether the perform name checking in the PKIX layer.
     *
     * <p>
     * Defaults to "true", should generally be disabled when used with an HTTP client
     * that is already checking names.
     * </p>
     *
     * <p>
     * If true a default implementation will be used unless a specific name evaluator impl has been supplied.
     * See also: {@link #setCredentialNameEvaluator(X509CredentialNameEvaluator)}.
     * </p>
     *
     * @param flag flag to set
     * 
     * @since 3.4.0
     */
    public void setCheckNames(final boolean flag) {
        checkNames = flag;
    }
    
    /**
     * Set explicitly trusted names to match against credential.
     * 
     * @param names explicitly trusted names
     * 
     * @since 3.4.0
     */
    public void setTrustedNames(@Nullable final Collection<String> names) {
        if (names != null) {
            trustedNames = CollectionSupport.copyToSet(names);
        } else {
            trustedNames = null;
        }
    }

    /**
     * Set the custom instance of {@link PKIXTrustEvaluator} to use.
     *
     * @param evaluator {@link PKIXTrustEvaluator} to set
     */
    public void setTrustEvaluator(@Nullable final PKIXTrustEvaluator evaluator) {
        trustEvaluator = evaluator;
    }

    /**
     * Set the custom instance of {@link X509CredentialNameEvaluator} to use.
     *
     * <p>
     * A non-null value overrides {@link #setCheckNames(boolean)}.
     * </p>
     *
     * @param evaluator {@link X509CredentialNameEvaluator} to set
     */
    public void setCredentialNameEvaluator(@Nullable final X509CredentialNameEvaluator evaluator) {
        credentialNameEvaluator = evaluator;
    }

    /**
     * Get the configured certificates.
     * 
     * @return the certificates
     */
    @Nonnull @Unmodifiable @NotLive protected List<X509Certificate> getCertificates() {
        if (certificateResources == null) {
            return CollectionSupport.emptyList();
        }
        
        assert certificateResources != null;
        final List<X509Certificate> certificates = new ArrayList<>(certificateResources.size());
        assert certificateResources != null;
        for (final Resource f : certificateResources) {
            try(final InputStream is = f.getInputStream()) {
                certificates.addAll(X509Support.decodeCertificates(is));
            } catch (final CertificateException | IOException e) {
                log.error("Could not decode Certificate at {}: {}", f.getDescription(), e.getMessage());
                throw new FatalBeanException("Could not decode provided CertificateFile: " + f.getDescription(), e);
            }
        }
        return certificates;
    }

    /**
     * Get the configured CRL list.
     * 
     * @return the crls
     */
    @Nonnull @Unmodifiable @NotLive protected List<X509CRL> getCRLs() {
        if (crlResources == null) {
            return CollectionSupport.emptyList();
        }
        
        assert crlResources != null;
        final List<X509CRL> crls = new ArrayList<>(crlResources.size());
        assert crlResources != null;
        for (final Resource crlFile : crlResources) {
            try(final InputStream is = crlFile.getInputStream())  {
                crls.addAll(X509Support.decodeCRLs(is));
            } catch (final CRLException | IOException e) {
                log.error("Could not decode CRL file at {}: {}", crlFile.getDescription(), e.getMessage());
                throw new FatalBeanException("Could not decode provided CRL file " + crlFile.getDescription(), e);
            }
        }
        return crls;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected PKIXX509CredentialTrustEngine doCreateInstance() throws Exception {
        final BasicPKIXValidationInformation info =
                new BasicPKIXValidationInformation(getCertificates(), getCRLs(), verifyDepth);
        
        final StaticPKIXValidationInformationResolver resolver =
                new StaticPKIXValidationInformationResolver(CollectionSupport.singletonList(info), trustedNames, checkNames);

        final PKIXTrustEvaluator pkixTrustEvaluator =
                trustEvaluator != null ? trustEvaluator : new CertPathPKIXTrustEvaluator();

        final X509CredentialNameEvaluator credNameEvaluator =
                credentialNameEvaluator != null ? credentialNameEvaluator :
                    (checkNames ? new BasicX509CredentialNameEvaluator() : null);

        validateConfiguration(pkixTrustEvaluator);

        return new PKIXX509CredentialTrustEngine(resolver, pkixTrustEvaluator, credNameEvaluator);
    }

    /**
     * Validate the configuration of the effective {@link PKIXTrustEvaluator}.
     *
     * @param pkixTrustEvaluator the instance whose configuration is to be evaluated
     *
     * @throws Exception if configuration issues are encountered
     */
    protected void validateConfiguration(@Nonnull final PKIXTrustEvaluator pkixTrustEvaluator) throws Exception {
        if (CertPathPKIXTrustEvaluator.class.isInstance(pkixTrustEvaluator)
                && CertPathPKIXValidationOptions.class.isInstance(pkixTrustEvaluator.getPKIXValidationOptions())) {
            
            final CertPathPKIXValidationOptions certPathOptions =
                    CertPathPKIXValidationOptions.class.cast(pkixTrustEvaluator.getPKIXValidationOptions());

           if (certPathOptions.isForceRevocationEnabled() && certPathOptions.isRevocationEnabled()
                   && getCRLs().isEmpty()
                   && ! Boolean.getBoolean("com.sun.security.enableCRLDP")
                   && ! "true".equalsIgnoreCase(StringSupport.trimOrNull(Security.getProperty("oscp.enable"))) ) {

               log.error("Certificate revocation checking was force enabled, "
                       + "but no static CRLs were supplied and both CRLDP and OCSP processing is disabled");

               throw new FatalBeanException("Certificate revocation checking was force enabled, "
                       + "but no static CRLs were supplied and both CRLDP and OCSP processing is disabled");
           }
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Call a destroy method if aposite.</p>
     * <p> We do not call the parent tear down so as to avoid any deprecation logging</>
     */
    @Override protected void destroyInstance(@Nullable final PKIXX509CredentialTrustEngine instance) throws Exception {
        AnnotationsSupport.callOnTeardownAnnotations(instance);
    }
}
