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

package org.opensaml.saml.common.binding.artifact;

import java.util.Arrays;
import java.util.HexFormat;

import javax.annotation.Nonnull;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.codec.Base64Support;
import net.shibboleth.shared.codec.EncodingException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

import org.slf4j.Logger;

/**
 * Base class for SAML artifacts.
 */
public abstract class AbstractSAMLArtifact implements SAMLArtifact {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractSAMLArtifact.class);

    /** 2 byte artifact type code. */
    @Nonnull private byte[] typeCode;

    /**
     * Constructor.
     * 
     * @param code the artifact type code
     * 
     * @throws IllegalArgumentException thrown if the given type code is not two bytes in length
     */
    protected AbstractSAMLArtifact(@Nonnull final byte[] code) {
        if (code.length != 2) {
            throw new IllegalArgumentException("Type code was not 2-bytes in size");
        }
        typeCode = code;
    }

    /** {@inheritDoc} */
    @Nonnull public byte[] getArtifactBytes() {
        final byte[] remainingArtifact = getRemainingArtifact();
        final byte[] artifact = new byte[2 + remainingArtifact.length];

        System.arraycopy(getTypeCode(), 0, artifact, 0, 2);
        System.arraycopy(remainingArtifact, 0, artifact, 2, remainingArtifact.length);

        return artifact;
    }

    /** {@inheritDoc} */
    @Nonnull public byte[] getTypeCode() {
        return typeCode;
    }

    /**
     * Sets the 2 byte type code for this artifact.
     * 
     * @param newTypeCode 2 byte type code for this artifact
     */
    protected void setTypeCode(@Nonnull final byte[] newTypeCode) {
        typeCode = Constraint.isNotNull(newTypeCode, "Type code cannot be null");
    }
 
    /**
     * Gets the artifact bytes minus the type code.
     * 
     * @return artifact bytes minus the type code
     */
    @Nonnull public abstract byte[] getRemainingArtifact();

    /**
     * Gets the Base64 encoded artifact.
     * 
     * @return Base64 encoded artifact.
     * @throws EncodingException if the artifact could not be base64 encoded.
     */
    @Nonnull @NotEmpty public String base64Encode() throws EncodingException {
        return Base64Support.encode(getArtifactBytes(), Base64Support.UNCHUNKED);
    }

    /**
     * Gets the hex encoded artifact.
     * 
     * @return hex encoded artifact
     */
    @Nonnull @NotEmpty public String hexEncode() {
        return HexFormat.of().formatHex(getArtifactBytes());
    }

    /** {@inheritDoc} */
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof SAMLArtifact) {
            final SAMLArtifact otherArtifact = (SAMLArtifact) o;
            return Arrays.equals(getArtifactBytes(), otherArtifact.getArtifactBytes());
        }

        return false;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return Arrays.hashCode(getArtifactBytes());
    }

    /** {@inheritDoc} */
    public String toString() {
        try {
            return base64Encode();
        } catch (final EncodingException e) {
            log.warn("Could not base64 encode SAML artifact for toString representation: {}",e.getMessage());
            return "";
        }
    }
}