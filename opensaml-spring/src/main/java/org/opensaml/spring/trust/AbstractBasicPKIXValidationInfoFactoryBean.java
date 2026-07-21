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

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.x509.impl.BasicPKIXValidationInformation;

import net.shibboleth.shared.primitive.AnnotationsSupport;
import net.shibboleth.shared.spring.factory.AbstractComponentAwareFactoryBean;

/**
 * A factory bean to collect information to do with a {@link BasicPKIXValidationInformation}.
 *
 * TODO: Remove the {@link #destroyInstance()} from this class in V6.
 */
public abstract class AbstractBasicPKIXValidationInfoFactoryBean extends
        AbstractComponentAwareFactoryBean<BasicPKIXValidationInformation> {

    /** Verification depth. */
    @Nullable private Integer verifyDepth;

    /** The description of the file with the configuration us. */
    @Nullable private String configDescription;

    /**
     * Get the verify Depth.
     * 
     * @return Returns the depth.
     */
    @Nullable public Integer getVerifyDepth() {
        return verifyDepth;
    }

    /**
     * Set the verify Depth.
     * 
     * @param depth The value to set.
     */
    public void setVerifyDepth(@Nullable final Integer depth) {
        verifyDepth = depth;
    }

    /**
     * For logging, get the description of the resource that defined this bean.
     * 
     * @return Returns the description.
     */
    @Nullable public String getConfigDescription() {
        return configDescription;
    }

    /**
     * For logging, set the description of the resource that defined this bean.
     * 
     * @param desc what to set.
     */
    public void setConfigDescription(@Nullable final String desc) {
        configDescription = desc;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull public Class<?> getObjectType() {
        return BasicPKIXValidationInformation.class;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected BasicPKIXValidationInformation doCreateInstance() throws Exception {
        return new BasicPKIXValidationInformation(getCertificates(), getCRLs(), verifyDepth);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Call a destroy method if aposite.</p>
     * <p> We do not call the parent tear down so as to avoid any deprecation logging</>
     */
    @Override protected void destroyInstance(@Nullable final BasicPKIXValidationInformation instance) throws Exception {
        AnnotationsSupport.callOnTeardownAnnotations(instance);
    }

    /**
     * Get the configured certificates.
     * 
     * @return the certificates.
     */
    @Nullable protected abstract List<X509Certificate> getCertificates();

    /**
     * Get the configured CRL list.
     * 
     * @return the crls or null
     */
    @Nullable protected abstract List<X509CRL> getCRLs();

}
