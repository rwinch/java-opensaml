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

package org.opensaml.security.config;

import java.time.Duration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.httpclient.HttpClientSecurityConfiguration;
import org.opensaml.security.x509.tls.ClientTLSValidationConfiguration;

import net.shibboleth.shared.security.IdentifierGenerationStrategy;

/**
 * General security settings for profiles.
 * 
 * @since 5.0.0
 */
public interface SecurityConfiguration {

    /**
     * Get the acceptable clock skew.
     * 
     * @return acceptable clock skew
     * 
     * @deprecated
     */
    @Deprecated(since="5.3.0", forRemoval=true)
    @Nonnull Duration getClockSkew();

    /**
     * Get the generator used to generate secure identifiers.
     * 
     * @return generator used to generate secure identifiers
     */
    @Nonnull IdentifierGenerationStrategy getIdGenerator();

    /**
     * Get the configuration used when validating client TLS X509Credentials.
     * 
     * @return configuration used when validating client TLS X509Credentials, or null
     */
    @Nullable ClientTLSValidationConfiguration getClientTLSValidationConfiguration();

    /**
     * Get the configuration used when executing HttpClient requests.
     * 
     * @return configuration used when executing HttpClient requests, or null
     */
    @Nullable HttpClientSecurityConfiguration getHttpClientSecurityConfiguration();

}