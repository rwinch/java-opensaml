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

package org.opensaml.security.credential.criteria.impl;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.logic.AbstractTriStatePredicate;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509SubjectKeyIdentifierCriterion;
import org.opensaml.security.x509.X509Support;
import org.slf4j.Logger;

/**
 * Instance of evaluable credential criteria for evaluating whether a credential's certificate contains a particular
 * subject key identifier.
 */
public class EvaluableX509SubjectKeyIdentifierCredentialCriterion extends AbstractTriStatePredicate<Credential>
        implements EvaluableCredentialCriterion {
    
    /** Logger. */
    @Nonnull private final Logger log =
            LoggerFactory.getLogger(EvaluableX509SubjectKeyIdentifierCredentialCriterion.class);
    
    /** Base criteria. */
    @Nonnull private final byte[] ski;
    
    /**
     * Constructor.
     *
     * @param criteria the criteria which is the basis for evaluation
     */
    public EvaluableX509SubjectKeyIdentifierCredentialCriterion(
            @Nonnull final X509SubjectKeyIdentifierCriterion criteria) {
        ski = Constraint.isNotNull(criteria, "Criterion instance cannot be null").getSubjectKeyIdentifier();
    }
    
    /**
     * Constructor.
     *
     * @param newSKI the criteria value which is the basis for evaluation
     */
    public EvaluableX509SubjectKeyIdentifierCredentialCriterion(@Nonnull final byte[] newSKI) {
        ski = Constraint.isNotEmpty(newSKI, "Subject key identifier cannot be null or empty");
    }

    /** {@inheritDoc} */
    public boolean test(@Nullable final Credential target) {
        if (target == null) {
            log.error("Credential target was null");
            return isNullInputSatisfies();
        } else if (!(target instanceof X509Credential)) {
            log.info("Credential is not an X509Credential, does not satisfy subject key identifier criteria");
            return false;
        }
        
        final X509Certificate entityCert = ((X509Credential) target).getEntityCertificate();
        
        final byte[] credSKI = X509Support.getSubjectKeyIdentifier(entityCert);
        if (credSKI == null || credSKI.length == 0) {
            log.info("Could not evaluate criteria, certificate contained no subject key identifier extension");
            return isUnevaluableSatisfies();
        }
        
        return Arrays.equals(ski, credSKI);
    }
    
    /** {@inheritDoc} */
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("EvaluableX509SubjectKeyIdentifierCredentialCriterion [ski=");
        builder.append(HexFormat.of().formatHex(ski));
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return ski.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof EvaluableX509SubjectKeyIdentifierCredentialCriterion other) {
            return ski.equals(other.ski);
        }

        return false;
    }

}
