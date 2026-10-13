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

package org.opensaml.saml.saml2.binding.artifact;

import java.util.Base64;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.codec.DecodingException;
import net.shibboleth.shared.collection.CollectionSupport;

/**
 * Factory used to construct SAML 2 artifact builders.
 */
public class SAML2ArtifactBuilderFactory {

    /** Registered artifact builders. */
    @Nonnull private Map<String, SAML2ArtifactBuilder<?>> artifactBuilders;

    /** Constructor. */
    public SAML2ArtifactBuilderFactory() {
        artifactBuilders = CollectionSupport.singletonMap(
                new String(SAML2ArtifactType0004.TYPE_CODE), new SAML2ArtifactType0004Builder());
    }

    /**
     * Gets the currently registered artifact builders.
     * 
     * @return currently registered artifact builders
     */
    @Nonnull @NotLive @Unmodifiable public Map<String, SAML2ArtifactBuilder<?>> getArtifactBuilders() {
        return artifactBuilders;
    }

    /**
     * Gets the artifact builder for the given type.
     * 
     * @param type type of artifact to be built
     * 
     * @return artifact builder for the given type
     */
    @Nullable public SAML2ArtifactBuilder<?> getArtifactBuilder(@Nonnull final byte[] type) {
        return artifactBuilders.get(new String(type));
    }
    
    /**
     * Convenience method for getting an artifact builder and parsing the given Base64 encoded artifact with it.
     * 
     * @param base64Artifact Base64 encoded artifact to parse
     * 
     * @return constructed artifact
     * 
     * @throws DecodingException if the <code>base64Artifact</code> could not be base64-decoded.
     */
    @Nullable public SAML2Artifact buildArtifact(@Nonnull final String base64Artifact) throws DecodingException{
        final byte[] decoded;
        try {
            decoded = Base64.getMimeDecoder().decode(base64Artifact);
        } catch (final IllegalArgumentException e) {
            throw new DecodingException("Unable to base64 decode data: " + e.getMessage(), e);
        }
        return buildArtifact(decoded);
    }

    /**
     * convenience method for getting an artifact builder and parsing the given artifact with it.
     * 
     * @param artifact artifact to parse
     * 
     * @return constructed artifact
     */
    @Nullable public SAML2Artifact buildArtifact(@Nullable final byte[] artifact) {
        if(artifact == null){
            return null;
        }
        
        final byte[] type = new byte[2];
        type[0] = artifact[0];
        type[1] = artifact[1];

        final SAML2ArtifactBuilder<?> artifactBuilder = getArtifactBuilder(type);
        if (artifactBuilder == null) {
            throw new IllegalArgumentException("Saw unsupported artifact type: " + new String(type));
        }
        return artifactBuilder.buildArtifact(artifact);
    }

}