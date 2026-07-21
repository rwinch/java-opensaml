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

package org.opensaml.security.credential.impl;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.credential.AbstractCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;

import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * Simple implementation of {@link CredentialResolver} which just stores
 * and returns a static set of credentials.
 * 
 * <p>
 * Note: no filtering or other evaluation of the credentials is performed.  Any Criterion
 * specified are ignored.  For a similar Collection-based CredentialResolver implementation which does support 
 * evaluation and filtering based on supplied evaluable criteria, see {@link CollectionCredentialResolver}.
 * </p>
 */
public class StaticCredentialResolver extends AbstractCredentialResolver {
    
    /** List of credentials held by this resolver. */
    @Nonnull private final List<Credential> creds;
    
    /**
     * Constructor.
     *
     * @param credentials collection of credentials to be held by this resolver
     */
    public StaticCredentialResolver(@Nonnull @ParameterName(name="credentials") final List<Credential> credentials) {
        Constraint.isNotNull(credentials, "Input credentials list cannot be null");
        
        creds = CollectionSupport.copyToList(credentials);
    }
    
    /**
     * Constructor.
     *
     * @param credential a single credential to be held by this resolver
     */
    public StaticCredentialResolver(@Nonnull @ParameterName(name="credential") final Credential credential) {
        Constraint.isNotNull(credential, "Input credential cannot be null");
        
        creds = CollectionSupport.singletonList(credential);
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull public Iterable<Credential> resolve(@Nullable final CriteriaSet criteria) throws ResolverException {
        return creds;
    }

}