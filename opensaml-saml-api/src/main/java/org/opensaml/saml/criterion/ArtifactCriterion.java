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

package org.opensaml.saml.criterion;

import java.util.HexFormat;
import java.util.Objects;

import javax.annotation.Nonnull;

import org.opensaml.saml.common.binding.artifact.SAMLArtifact;

import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.resolver.Criterion;

/** {@link Criterion} representing a {@link SAMLArtifact}. */
public final class ArtifactCriterion implements Criterion {

    /** The SourceID value. */
    @Nonnull private final SAMLArtifact artifact;

    /**
     * Constructor.
     * 
     * @param newArtifact the artifact value
     */
    public ArtifactCriterion(@Nonnull final SAMLArtifact newArtifact) {
        artifact = Constraint.isNotNull(newArtifact, "SAMLArtifact cannot be null");
    }

    /**
     * Get the SAML artifact.
     * 
     * @return the SAML artifact
     */
    @Nonnull public SAMLArtifact getArtifact() {
        return artifact;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("ArtifactCriterion [artifact=");
        builder.append(HexFormat.of().formatHex(artifact.getArtifactBytes()));
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return artifact.hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof ArtifactCriterion other) {
            return Objects.equals(artifact, other.artifact);
        }

        return false;
    }
}