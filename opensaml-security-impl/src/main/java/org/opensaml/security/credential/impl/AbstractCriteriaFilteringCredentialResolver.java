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

import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.logic.PredicateSupport;
import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.resolver.Criterion;
import net.shibboleth.shared.resolver.ResolverException;

import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.AbstractCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.criteria.impl.EvaluableCredentialCriteriaRegistry;
import org.opensaml.security.credential.criteria.impl.EvaluableCredentialCriterion;

import com.google.common.collect.Iterables;

/**
 * An abstract implementation of {@link org.opensaml.security.credential.CredentialResolver} that
 * filters the returned Credentials based on the instances of {@link Predicate}
 * which are present in the set of criteria as instances of {@link EvaluableCredentialCriterion}, 
 * or which are obtained via lookup in the {@link EvaluableCredentialCriteriaRegistry}.
 */
public abstract class AbstractCriteriaFilteringCredentialResolver extends AbstractCredentialResolver {
    
    /** Flag which determines whether predicates used in filtering are connected by 
     * a logical 'AND' or by logical 'OR'. */
    private boolean satisfyAllPredicates;
    
    /**
     * Constructor.
     */
    public AbstractCriteriaFilteringCredentialResolver() {
        satisfyAllPredicates = true;
    }

    /** {@inheritDoc} */
    @Nonnull public Iterable<Credential> resolve(@Nullable final CriteriaSet criteriaSet) throws ResolverException {
        final Iterable<Credential> storeCandidates = resolveFromSource(criteriaSet);
        final Set<Predicate<Credential>> predicates = getPredicates(criteriaSet);
        if (predicates.isEmpty()) {
            return storeCandidates;
        }
        
        Predicate<Credential> aggregatePredicate = null;
        if (isSatisfyAllPredicates()) {
            aggregatePredicate = PredicateSupport.and(predicates);
        } else {
            aggregatePredicate = PredicateSupport.or(predicates);
        }
        return Iterables.filter(storeCandidates, aggregatePredicate::test);
    }
    
    /**
     * Get the flag indicating whether resolved credentials must satisfy all predicates 
     * (i.e. connected by logical 'AND') or only one or more (connected by logical 'OR').
     * 
     * @return true if must satisfy all, false otherwise
     */
    public boolean isSatisfyAllPredicates() {
        return satisfyAllPredicates;
    }

    /**
     * Set the flag indicating whether resolved credentials must satisfy all predicates 
     * (i.e. connected by logical 'AND') or only one or more (connected by logical 'OR').
     * 
     * @param flag true if must satisfy all, false otherwise
     */
    public void setSatisfyAllPredicates(final boolean flag) {
        satisfyAllPredicates = flag;
    }

    /**
     * Subclasses are required to implement this method to resolve credentials from the 
     * implementation-specific type of underlying credential source.
     * 
     * @param criteriaSet the set of criteria used to resolve credentials from the credential source
     * @return an Iterable for the resolved set of credentials
     * @throws ResolverException thrown if there is an error resolving credentials from the credential source
     */
    @Nonnull protected abstract Iterable<Credential> resolveFromSource(@Nullable final CriteriaSet criteriaSet)
        throws ResolverException;

    /**
     * Construct a set of credential predicates based on the criteria set.
     * 
     * @param criteriaSet the set of credential criteria to process.
     * @return a set of Credential predicates
     * @throws ResolverException thrown if there is an error obtaining an instance of EvaluableCredentialCriterion
     *                           from the EvaluableCredentialCriteriaRegistry
     */
    @Nonnull private Set<Predicate<Credential>> getPredicates(@Nullable final CriteriaSet criteriaSet)
            throws ResolverException {
        if (criteriaSet == null) {
            return CollectionSupport.emptySet();
        }
        final Set<Predicate<Credential>> predicates = new HashSet<>(criteriaSet.size());
        for (final Criterion criteria : criteriaSet) {
            assert criteria != null;
            if (criteria instanceof EvaluableCredentialCriterion) {
                predicates.add((EvaluableCredentialCriterion) criteria);
            } else {
                final EvaluableCredentialCriterion evaluableCriteria;
                try {
                    evaluableCriteria = EvaluableCredentialCriteriaRegistry.getEvaluator(criteria);
                } catch (final SecurityException e) {
                    throw new ResolverException("Exception obtaining EvaluableCredentialCriterion", e);
                }
                if (evaluableCriteria != null) {
                    predicates.add(evaluableCriteria);
                }
            }
        }
        return predicates;
    }

}