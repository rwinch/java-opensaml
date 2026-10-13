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

package org.opensaml.security.x509;

import java.util.HexFormat;

import javax.annotation.Nonnull;

import net.shibboleth.shared.resolver.Criterion;

/**
 * An implementation of {@link Criterion} which specifies criteria based on
 * X.509 certificate subject key identifier.
 */
public final class X509SubjectKeyIdentifierCriterion implements Criterion {
    
    /** X.509 certificate subject key identifier. */
    @Nonnull private byte[] subjectKeyIdentifier;
    
    /**
     * Constructor.
     *
     * @param ski certificate subject key identifier
     */
    public X509SubjectKeyIdentifierCriterion(@Nonnull final byte[] ski) {
        if (ski == null || ski.length == 0) {
            throw new IllegalArgumentException("Subject key identifier criteria value cannot be null or empty");
        }
        subjectKeyIdentifier = ski;
    }
    
    /**
     * Get the subject key identifier.
     * 
     * @return Returns the subject key identifier
     */
    @Nonnull public byte[] getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    /**
     * Set the subject key identifier.
     * 
     * @param ski The subject key identifier to set.
     */
    public void setSubjectKeyIdentifier(@Nonnull final byte[] ski) {
        if (ski == null || ski.length == 0) {
            throw new IllegalArgumentException("Subject key identifier criteria value cannot be null or empty");
        }
        subjectKeyIdentifier = ski;
    }
    
    /** {@inheritDoc} */
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("X509SubjectKeyIdentifierCriterion [subjectKeyIdentifier=");
        builder.append(HexFormat.of().formatHex(subjectKeyIdentifier));
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return subjectKeyIdentifier.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof X509SubjectKeyIdentifierCriterion other) {
            return subjectKeyIdentifier.equals(other.subjectKeyIdentifier);
        }

        return false;
    }

}