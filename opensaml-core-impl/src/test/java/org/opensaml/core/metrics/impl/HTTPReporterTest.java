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

package org.opensaml.core.metrics.impl;

import org.opensaml.core.metrics.MetricsSupport;
import org.opensaml.core.testing.OpenSAMLInitBaseTestCase;
import org.testng.annotations.Test;

import net.shibboleth.shared.httpclient.HttpClientBuilder;

/**
 * Unit test for {@link HTTPReporter}.
 */
public class HTTPReporterTest extends OpenSAMLInitBaseTestCase {

    /** Basic test of component's lifecycle. */
    @Test
    public void test() throws Exception {
     
        final HTTPReporter reporter = new HTTPReporter(MetricsSupport.getMetricRegistry(), "test", null);
        reporter.setCollectorURL("https://localhost/reporter");
        reporter.setHttpClient(new HttpClientBuilder().buildClient());
        reporter.initialize();
        
        reporter.stop();
    }
    
}