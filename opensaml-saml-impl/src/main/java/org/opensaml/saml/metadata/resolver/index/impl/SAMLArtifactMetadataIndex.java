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

package org.opensaml.saml.metadata.resolver.index.impl;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.binding.artifact.SAMLArtifact;
import org.opensaml.saml.common.binding.artifact.SAMLSourceIDArtifact;
import org.opensaml.saml.common.binding.artifact.SAMLSourceLocationArtifact;
import org.opensaml.saml.criterion.ArtifactCriterion;
import org.opensaml.saml.ext.saml1md.SourceID;
import org.opensaml.saml.metadata.resolver.index.MetadataIndex;
import org.opensaml.saml.metadata.resolver.index.MetadataIndexKey;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.opensaml.security.crypto.JCAConstants;
import org.slf4j.Logger;

import com.google.common.base.MoreObjects;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.collection.LazySet;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.resolver.CriteriaSet;

/**
 * An implementation of {@link MetadataIndex} which indexes entities by their artifact SourceID values.
 */
public class SAMLArtifactMetadataIndex implements MetadataIndex {
    
    /** Indexing function instance to use. */
    @Nonnull private List<Function<EntityDescriptor, Set<MetadataIndexKey>>> indexingFunctions;
    
    /**
     * Constructor.
     * 
     * <p>
     * The descriptor indexing functions will be:
     * </p>
     * <ul>
     *   <li>{@link EntityIDToSHA1SourceIDIndexingFunction}</li>
     *   <li>{@link SourceIDExtensionIndexingFunction}</li>
     *   <li>{@link SourceLocationIndexingFunction}</li>
     * </ul>
     */
    public SAMLArtifactMetadataIndex() {
        this(CollectionSupport.listOf(
                new EntityIDToSHA1SourceIDIndexingFunction(),
                new SourceIDExtensionIndexingFunction(),
                new SourceLocationIndexingFunction()
                ));
    }
    
    /**
     * Constructor.
     *
     * @param descriptorIndexingFunctions the functions used to produce index keys from an entity descriptor
     */
    public SAMLArtifactMetadataIndex(
            @Nonnull final List<Function<EntityDescriptor, Set<MetadataIndexKey>>> descriptorIndexingFunctions) {
        indexingFunctions = CollectionSupport.copyToList(
                Constraint.isNotNull(descriptorIndexingFunctions,
                        "EntityDescriptor indexing functions list may not be null"));
        Constraint.isNotEmpty(indexingFunctions, "EntityDescriptor indexing functions list may not be empty");
    }

    /** {@inheritDoc} */
    @Nullable @Unmodifiable @NotLive public Set<MetadataIndexKey> generateKeys(
            @Nonnull final EntityDescriptor descriptor) {
        Constraint.isNotNull(descriptor, "EntityDescriptor was null");
        final HashSet<MetadataIndexKey> results = new HashSet<>();
        for (final Function<EntityDescriptor, Set<MetadataIndexKey>> indexingFunction : indexingFunctions) {
            final Set<MetadataIndexKey> result = indexingFunction.apply(descriptor);
            if (result != null) {
                results.addAll(result);
            }
        }
        return results;
    }

    /** {@inheritDoc} */
    @Nullable @Unmodifiable @NotLive public Set<MetadataIndexKey> generateKeys(
            @Nullable final CriteriaSet criteriaSet) {
        final ArtifactCriterion artifactCrit = criteriaSet != null ? criteriaSet.get(ArtifactCriterion.class) : null;
        if (artifactCrit != null) {
            final LazySet<MetadataIndexKey> results = new LazySet<>();
            
            final SAMLArtifact artifact = artifactCrit.getArtifact();
            
            if (artifact instanceof SAMLSourceIDArtifact art) {
                results.add(new ArtifactSourceIDMetadataIndexKey(art.getSourceID()));
            }
            
            if (artifact instanceof SAMLSourceLocationArtifact art) {
                results.add(new ArtifactSourceLocationMetadataIndexKey(art.getSourceLocation()));
            }
            
            return results;
        }
        return null;
    }
    
    /**
     * Entity descriptor indexing function which produces a single 
     * {@link ArtifactSourceIDMetadataIndexKey} based on the SHA-1 digest of the UTF-8 encoding
     * of the value of {@link EntityDescriptor#getEntityID()}.
     */
    public static class EntityIDToSHA1SourceIDIndexingFunction 
        implements Function<EntityDescriptor, Set<MetadataIndexKey>> {
        
        /** Logger. */
        @Nonnull private Logger log = LoggerFactory.getLogger(EntityIDToSHA1SourceIDIndexingFunction.class);

        /** {@inheritDoc} */
        @Nullable public Set<MetadataIndexKey> apply(@Nullable final EntityDescriptor descriptor) {
            if (descriptor == null) {
                return null;
            }
            final String entityID = StringSupport.trimOrNull(descriptor.getEntityID());
            if (entityID == null) {
                return null;
            }
            
            try {
                final MessageDigest sha1Digester = MessageDigest.getInstance(JCAConstants.DIGEST_SHA1);
                final byte[] sourceID = sha1Digester.digest(entityID.getBytes("UTF-8"));
                assert sourceID != null;
                final ArtifactSourceIDMetadataIndexKey key = new ArtifactSourceIDMetadataIndexKey(sourceID);
                log.trace("For entityID '{}' produced artifact SourceID index key: {}", entityID, key);
                return CollectionSupport.singleton(key);
            } catch (final NoSuchAlgorithmException e) {
                // SHA-1 should be supported in every JVM, so this should never happen.
                log.error("Digest algorithm '{}' was invalid for encoding artifact SourceID", 
                        JCAConstants.DIGEST_SHA1, e);
                return null;
            } catch (final UnsupportedEncodingException e) {
                // UTF-8 should be supported in every JVM, this should never happen.
                log.error("UTF-8 was unsupported for encoding artifact SourceID!");
                return null;
            }
        }
        
    }
    
    /**
     * Descriptor indexing function which produces 0 to many {@link ArtifactSourceIDMetadataIndexKey} instances
     * based on the values of all {@link SourceID} extension elements present in the descriptor's
     * {@link RoleDescriptor}s.
     */
    public static class SourceIDExtensionIndexingFunction 
        implements Function<EntityDescriptor, Set<MetadataIndexKey>> {
        
        /** Logger. */
        @Nonnull private Logger log = LoggerFactory.getLogger(SourceIDExtensionIndexingFunction.class);

        /** {@inheritDoc} */
        @Nullable public Set<MetadataIndexKey> apply(@Nullable final EntityDescriptor descriptor) {
            if (descriptor == null) {
                return null;
            }
            
            final LazySet<MetadataIndexKey> results = new LazySet<>();
            
            for (final RoleDescriptor roleDescriptor : descriptor.getRoleDescriptors()) {
                final Extensions extensions = roleDescriptor.getExtensions();
                if (extensions != null) {
                    final List<XMLObject> children = extensions.getUnknownXMLObjects(SourceID.DEFAULT_ELEMENT_NAME);
                    if (children != null && !children.isEmpty()) {
                        final QName role = descriptor.getSchemaType() != null ? roleDescriptor.getSchemaType() 
                                : roleDescriptor.getElementQName();
                        log.trace("Processing SourceID extensions for entityID '{}' with role '{}'", 
                                descriptor.getEntityID(), role);
                        
                        for (final XMLObject child : children) {
                            final SourceID extSourceID = (SourceID) child;
                            final String extSourceIDHex = StringSupport.trimOrNull(extSourceID.getValue());
                            if (extSourceIDHex != null) {
                                try {
                                    final byte[] sourceID = HexFormat.of().parseHex(extSourceIDHex);
                                    assert sourceID != null;
                                    final ArtifactSourceIDMetadataIndexKey key = 
                                            new ArtifactSourceIDMetadataIndexKey(sourceID);
                                    log.trace("For SourceID extension value '{}' produced index key: {}", 
                                            extSourceIDHex, key);
                                    results.add(key);
                                } catch (final IllegalArgumentException e) {
                                    log.warn("Error decoding hexidecimal SourceID extension value '{}' for indexing", 
                                            extSourceIDHex, e);
                                }
                            }
                        }
                    }
                }
            }
            
            
            return results;
        }
        
    }
    
    /**
     * Descriptor indexing function which produces 0 to many {@link ArtifactSourceLocationMetadataIndexKey} instances
     * based on the location values of all {@link ArtifactResolutionService} elements present in the descriptor's
     * {@link RoleDescriptor}s.
     */
    public static class SourceLocationIndexingFunction implements Function<EntityDescriptor, Set<MetadataIndexKey>> {
        
        /** Logger. */
        @Nonnull private Logger log = LoggerFactory.getLogger(SourceLocationIndexingFunction.class);

        /** {@inheritDoc} */
        @Nullable public Set<MetadataIndexKey> apply(@Nullable final EntityDescriptor descriptor) {
            if (descriptor == null) {
                return null;
            }
            
            final LazySet<MetadataIndexKey> results = new LazySet<>();
            
            for (final RoleDescriptor roleDescriptor : descriptor.getRoleDescriptors()) {
                if (roleDescriptor instanceof SSODescriptor sso) {
                    final List<ArtifactResolutionService> arsList = sso.getArtifactResolutionServices();
                    if (!arsList.isEmpty()) {
                        final QName role = descriptor.getSchemaType() != null ? roleDescriptor.getSchemaType() 
                                : roleDescriptor.getElementQName();
                        log.trace("Processing ArtifactResolutionService locations for entityID '{}' with role '{}'", 
                                descriptor.getEntityID(), role);
                        
                        for (final ArtifactResolutionService ars : arsList) {
                            final String location = ars.getLocation();
                            if (location != null) {
                                final ArtifactSourceLocationMetadataIndexKey key =
                                        new ArtifactSourceLocationMetadataIndexKey(location);
                                log.trace("For entityID '{}' produced artifact source location index key: {}",
                                        descriptor.getEntityID(), key);
                                results.add(key);
                            }
                        }
                    }
                }
            }
            
            return results;
        }
        
    }
    
    /**
     * An implementation of {@link MetadataIndexKey} representing a SAML artifact SourceID value.
     */
    protected static class ArtifactSourceIDMetadataIndexKey implements MetadataIndexKey {
        
        /** The SourceID value. */
        @Nonnull @NotEmpty private final byte[] sourceID;

        /**
         * Constructor.
         * 
         * @param newSourceID the artifact SourceID value
         */
        public ArtifactSourceIDMetadataIndexKey(@Nonnull @NotEmpty final byte[] newSourceID) {
            sourceID = Constraint.isNotNull(newSourceID, "SourceID cannot be null");
            Constraint.isGreaterThan(0, sourceID.length, "SourceID length must be greater than zero");
        }

        /**
         * Get the SourceID value.
         * 
         * @return the SourceID value
         */
        @Nonnull @NotEmpty public byte[] getSourceID() {
            return sourceID;
        }

        /** {@inheritDoc} */
        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("sourceID", HexFormat.of().formatHex(sourceID))
                    .toString();
        }

        /** {@inheritDoc} */
        @Override
        public int hashCode() {
            return Arrays.hashCode(sourceID);
        }

        /** {@inheritDoc} */
        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }

            if (obj instanceof ArtifactSourceIDMetadataIndexKey other) {
                return Arrays.equals(sourceID, other.getSourceID());
            }

            return false;
        }
        
    }
    
    /**
     * An implementation of {@link MetadataIndexKey} representing a SAML artifact source location value.
     */
    protected static class ArtifactSourceLocationMetadataIndexKey implements MetadataIndexKey {
        
        /** Logger. */
        @Nonnull private Logger log = LoggerFactory.getLogger(ArtifactSourceLocationMetadataIndexKey.class);
        
        /** The location. */
        @Nonnull private final String location;
        
        /** The location. */
        @Nonnull private String canonicalizedLocation;
        
        /** Flag indicating whether canonicalized location is the simple lower case fallback strategy. */
        private boolean isCanonicalizedLowerCase;
        
        /**
         * Constructor.
         * 
         * @param sourceLocation the source location
         */
        public ArtifactSourceLocationMetadataIndexKey(@Nonnull @NotEmpty final String sourceLocation) {
            location = Constraint.isNotNull(StringSupport.trimOrNull(sourceLocation),
                    "SAML artifact source location cannot be null or empty");
            try {
                canonicalizedLocation = MetadataIndexSupport.canonicalizeLocationURI(location);
            } catch (final MalformedURLException e) {
                // This is unlikely to happen on realistic real world inputs. If it does, don't be fatal, 
                // just switch to alternate strategy.
                log.warn("Input source location '{}' was a malformed URL, switching to lower case strategy", 
                        location, e);
                canonicalizedLocation = location.toLowerCase();
                isCanonicalizedLowerCase = true;
            }
        }

        /**
         * Gets the location.
         * 
         * @return the location
         */
        @Nonnull public String getLocation() {
            return location;
        }
        
        /**
         * Get the canonicalized representation of the location, primarily for use in
         * {@link #hashCode()} and {@link #equals(Object)}.
         * 
         * @return the canonicalized source location
         */
        @Nonnull public String getCanonicalizedLocation() {
            return canonicalizedLocation;
        }
        
        /** {@inheritDoc} */
        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("location", location)
                    .add("canonicalizedLocation", canonicalizedLocation)
                    .add("isCanonicalizedLowerCase", isCanonicalizedLowerCase)
                    .toString();
        }

        /** {@inheritDoc} */
        @Override
        public int hashCode() {
            return canonicalizedLocation.hashCode();
        }

        /** {@inheritDoc} */
        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }

            if (obj instanceof ArtifactSourceLocationMetadataIndexKey other) {
                if (this.isCanonicalizedLowerCase == other.isCanonicalizedLowerCase) {
                    return this.canonicalizedLocation.equals(other.canonicalizedLocation);
                }
                if (this.isCanonicalizedLowerCase) {
                    return this.canonicalizedLocation.equals(other.location.toLowerCase());
                }
                return other.canonicalizedLocation.equals(this.location.toLowerCase());
            }

            return false;
        }
        
    }

}
