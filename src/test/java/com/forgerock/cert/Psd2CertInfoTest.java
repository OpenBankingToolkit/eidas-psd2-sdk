/**
 *
 * The contents of this file are subject to the terms of the Common Development and
 *  Distribution License (the License). You may not use this file except in compliance with the
 *  License.
 *
 *  You can obtain a copy of the License at https://forgerock.org/cddlv1-0/. See the License for the
 *  specific language governing permission and limitations under the License.
 *
 *  When distributing Covered Software, include this CDDL Header Notice in each file and include
 *  the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 *  Header, with the fields enclosed by brackets [] replaced by your own identifying
 *  information: "Portions copyright [year] [name of copyright owner]".
 *
 *  Copyright 2019 ForgeRock AS.
 */
package com.forgerock.cert;

import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.exception.NoSuchRDNInField;
import com.forgerock.cert.utils.CertificateUtils;
import com.forgerock.cert.utils.RdnField;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;

class CertificateTestSpec {
    private String certName;
    private String filePath;
    private Boolean isPsd2Cert;

    public CertificateTestSpec(String certName, String filePath, Boolean isPsd2Cert) {
        this.certName = certName;
        this.filePath = filePath;
        this.isPsd2Cert = isPsd2Cert;
    }

    public X509Certificate[] getCert() throws IOException, CertificateException {
        return getCertFromFile(this.filePath);
    }

    private X509Certificate[] getCertFromFile(String path) throws IOException, CertificateException {
        FileInputStream fis = null;
        try{
            fis = new FileInputStream(path);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return new X509Certificate[]{(X509Certificate) certificateFactory.generateCertificate(fis)};
        } finally {
            if(fis != null) fis.close();
        }
    }

    public String getCertName() {
        return certName;
    }

    public Boolean isPsd2Cert() {
        return isPsd2Cert;
    }
}


@RunWith(Parameterized.class)
public class Psd2CertInfoTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data(){
        Set<Object[]> testCerts = new HashSet<Object[]>();
        testCerts.add(new Object[]{new CertificateTestSpec("FrDirectoryPsd2Certificate", "src/test/resources/dev-transport.pem", true)});
        testCerts.add(new Object[]{new CertificateTestSpec("FrDirectoryPrePsd2Cert", "src/test/resources/fr-directory.pem", false)});
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
    public void isPsd2CertTest() throws IOException, CertificateException, InvalidPsd2EidasCertificate {
        Psd2CertInfo psd2CertInfo = new Psd2CertInfo(testSpec.getCert());
        assertThat(psd2CertInfo, is(notNullValue()));
        assertThat(psd2CertInfo.isPsd2Cert(), is(testSpec.isPsd2Cert()));
    }

    @Test
    public void canReadAuthorityAccessInfo() throws IOException, CertificateException, InvalidPsd2EidasCertificate {
        Psd2CertInfo psd2CertInfo = new Psd2CertInfo(this.testSpec.getCert());
        Optional<AuthorityInformationAccess> authAccessInfo = psd2CertInfo.getAuthorityAccessInfo();
        assertThat(authAccessInfo.isPresent(), is(this.testSpec.isPsd2Cert()));
    }

    @Test
    public void getOrganisationId() throws NoSuchRDNInField, CertificateException, IOException {
        String expectedOrgId = "PSDGB-" + CertificateUtils.getRDNAsString(this.certs[0], RdnField.SUBJECT,
                BCStyle.OU);
        Optional<String> orgIdOptional = this.psd2CertInfo.getOrganizationId();
        assertThat(orgIdOptional.isPresent(), is(this.testSpec.isPsd2Cert()));
        if(this.testSpec.isPsd2Cert()) {
            assertThat(orgIdOptional.get(), is(expectedOrgId));
        }
    }

    @Test
    public void getApplicationId() throws NoSuchRDNInField, CertificateEncodingException {
        String applicationId = this.psd2CertInfo.getApplicationId();
        assertThat(applicationId, is(CertificateUtils.getRDNAsString(this.certs[0], RdnField.SUBJECT, BCStyle.CN)));
    }
}