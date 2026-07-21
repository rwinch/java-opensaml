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

package org.opensaml.security.criteria;

import javax.annotation.Nonnull;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.resolver.Criterion;

/**
 * An implementation of {@link Criterion} which specifies criteria pertaining 
 * to peer entity IDs.  This is typically used only in conjunction with a
 * {@link org.opensaml.core.criterion.EntityIdCriterion}, where the peer is interpreted to be relative
 * to that primary entity ID. In this sense it serves to scope the primary entity ID.
 * 
 * Note that the peer entity ID may be either local or remote,
 * depending on whether the associated primary entity ID is remote or local.
 * 
 * @deprecated
 */
@Deprecated(since="5.3.0", forRemoval=true)
public final class PeerEntityIDCriterion implements Criterion {
    
    /** Peer entity ID criteria. */
    @Nonnull @NotEmpty private String peerID;
    
    /**
    * Constructor.
     *
     * @param peer the entity ID which is the peer relative to a primary entity ID
     */
    public PeerEntityIDCriterion(@Nonnull @NotEmpty final String peer) {
        peerID = validatePeerID(peer);
    }

    /**
     * Get the entity ID which is the peer relative to a primary entity ID.
     * 
     * @return the peer entity ID.
     */
    @Nonnull @NotEmpty public String getPeerID() {
        return peerID;
    }

    /**
     * Set the entity ID which is the peer relative to a primary entity ID.
     * 
     * @param peer The peerID to set.
     */
    public void setPeerID(@Nonnull @NotEmpty final String peer) {
        peerID = validatePeerID(peer);
    }
    
    /** {@inheritDoc} */
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("PeerEntityIDCriterion [peerID=");
        builder.append(peerID);
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return peerID.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof PeerEntityIDCriterion peercrit) {
            return peerID.equals(peercrit.peerID);
        }

        return false;
    }
    
    /**
     * Validate peer ID criterion.
     * 
     * @param peer ID to check
     * 
     * @return the input if non-null/empty
     */
    @Nonnull @NotEmpty public String validatePeerID(@Nonnull @NotEmpty final String peer) {
        final String trimmed = StringSupport.trimOrNull(peer);

        return Constraint.isNotNull(trimmed, "Peer entityID criterion value cannot be null or empty");
    }

}