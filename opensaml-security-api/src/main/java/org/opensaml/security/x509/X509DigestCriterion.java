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

import java.util.Arrays;
import java.util.HexFormat;

import javax.annotation.Nonnull;

import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.resolver.Criterion;


/**
 * An implementation of {@link Criterion} which specifies criteria based on
 * the digest of an X.509 certificate.
 */
public final class X509DigestCriterion implements Criterion {
    
    /** Digest algorithm. */
    @Nonnull private String algorithm;
    
    /** X.509 certificate digest. */
    @Nonnull private byte[] x509digest;
    
    /**
     * Constructor.
     *
     * @param alg algorithm of digest computation
     * @param digest certificate digest
     */
    public X509DigestCriterion(@Nonnull final String alg, @Nonnull final byte[] digest) {
        algorithm = Constraint.isNotNull(
                StringSupport.trimOrNull(alg), "Certificate digest algorithm cannot be null or empty");
        x509digest = Constraint.isNotEmpty(digest, "Certificate digest criteria value cannot be null or empty");
    }

    /**
     * Get the digest algorithm.
     * 
     * @return the digest algorithm
     */
    @Nonnull public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Set the digest algorithm.
     * 
     * @param alg the digest algorithm to set
     */
    public void setAlgorithm(@Nonnull final String alg) {
        algorithm = Constraint.isNotNull(
                StringSupport.trimOrNull(alg), "Certificate digest algorithm cannot be null or empty");
    }
    
    /**
     * Get the certificate digest.
     * 
     * @return the digest
     */
    @Nonnull public byte[] getDigest() {
        return x509digest;
    }

    /**
     * Set the certificate digest.
     * 
     * @param digest the certificate digest to set
     */
    public void setDigest(@Nonnull final byte[] digest) {
        x509digest = Constraint.isNotEmpty(digest, "Certificate digest criteria value cannot be null or empty");
    }
    
    /** {@inheritDoc} */
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("X509DigestCriterion [algorithm=");
        builder.append(algorithm);
        builder.append(", digest=");
        builder.append(HexFormat.of().formatHex(x509digest));
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int result = 17;  
        result = 37*result + algorithm.hashCode();
        result = 37*result + x509digest.hashCode();
        return result;
    }

    /** {@inheritDoc} */
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof X509DigestCriterion other) {
            return algorithm.equals(other.algorithm) && Arrays.equals(x509digest, other.x509digest);
        }

        return false;
    }

}