/**
 * Copyright 2019 ForgeRock AS.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.forgerock.cert;

import com.forgerock.cert.eidas.EidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.exception.NoSuchRDNInField;
import com.forgerock.cert.utils.CertificateUtils;
import com.forgerock.cert.utils.RdnField;
import com.forgerock.test_helpers.RegexMatcher;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(Parameterized.class)
public class Psd2CertInfoTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data(){
        Set<Object[]> testCerts = new HashSet<Object[]>();
        testCerts.add(new Object[]{new CertificateTestSpec("FrDirectoryPsd2Certificate", "src/test/resources/dev" +
                "-transport.pem", true, EidasCertType.WEB)});
        testCerts.add(new Object[]{new CertificateTestSpec("OBDirectoryPsd2Certificate", "src/test/resources/ob-transport.pem", true, EidasCertType.WEB)});
        testCerts.add(new Object[]{new CertificateTestSpec("FrDirectoryPrePsd2Cert", "src/test/resources/fr-directory.pem", false, null)});
        testCerts.add(new Object[]{new CertificateTestSpec("FrDirectoryPrePsd2Cert", "src/test/resources/multicert" +
                "-psd2-eidas.cer",
                true, EidasCertType.WEB)});

        return testCerts;
    }

    private CertificateTestSpec testSpec;
    private Psd2CertInfo psd2CertInfo = null;
    private X509Certificate[] certs;

    public Psd2CertInfoTest(CertificateTestSpec testSpec) throws IOException, CertificateException, InvalidPsd2EidasCertificate {
        this.testSpec = testSpec;
        this.psd2CertInfo = new Psd2CertInfo(this.testSpec.getCert());
        this.certs = this.testSpec.getCert();
    }

    @Test
    public void isPsd2CertTest() throws Exception {
        Psd2CertInfo psd2CertInfo = new Psd2CertInfo(testSpec.getCert());
        assertThat(psd2CertInfo, is(notNullValue()));
        assertThat(psd2CertInfo.isPsd2Cert(), is(testSpec.isPsd2Cert()));
        if (psd2CertInfo.isPsd2Cert()) {
            assertThat(psd2CertInfo.getEidasCertType().isPresent(), is(true));
            assertThat(psd2CertInfo.getEidasCertType().get(), is(testSpec.getEidasCertType()));
        }
    }

    @Test
    public void canReadAuthorityAccessInfo() throws IOException, CertificateException, InvalidPsd2EidasCertificate {
        Psd2CertInfo psd2CertInfo = new Psd2CertInfo(this.testSpec.getCert());
        Optional<AuthorityInformationAccess> authAccessInfo = psd2CertInfo.getAuthorityAccessInfo();
        assertThat(authAccessInfo.isPresent(), is(this.testSpec.isPsd2Cert()));
    }

    @Test
    /**
     * So this tests that the Organisational Identifier matches the format specified in the spec.
     *
     * @see <a href="https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf">
     *     https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf</a>
     */
    public void getOrganisationId() throws NoSuchRDNInField, CertificateException, IOException {
        Optional<String> orgIdOptional = this.psd2CertInfo.getOrganizationId();
        assertThat(orgIdOptional.isPresent(), is(this.testSpec.isPsd2Cert()));
        if(this.testSpec.isPsd2Cert()) {
            assertThat(orgIdOptional.get(), RegexMatcher.matches("PSD[A-Z]{2}-[A-Z]{2,8}-.*"));
        }
    }

    @Test
    public void getApplicationId() throws NoSuchRDNInField, CertificateEncodingException {
        String applicationId = this.psd2CertInfo.getApplicationId();
        assertThat(applicationId, is(CertificateUtils.getRDNAsString(this.certs[0], RdnField.SUBJECT, BCStyle.CN)));
    }
}