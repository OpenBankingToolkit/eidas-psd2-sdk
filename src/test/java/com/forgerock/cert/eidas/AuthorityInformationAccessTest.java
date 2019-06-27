/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.cert.eidas;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;


public class AuthorityInformationAccessTest {

    @Test
    public void TestSerialisationDeserialization(){
        EidasInformation eidasInfo = new EidasInformation();
        eidasInfo.setOcspUri("http://test/oscp");
        eidasInfo.setCaIssuerCertURL("http://test/cert-uri");

        AccessDescription[] accessDescriptions = new AccessDescription[2];

        GeneralName caIssuerName = new GeneralName(GeneralName.uniformResourceIdentifier, eidasInfo.getCaIssuerCertURL());
        accessDescriptions[0] = new AccessDescription(AccessDescription.id_ad_caIssuers, caIssuerName);

        GeneralName oscpName = new GeneralName(GeneralName.uniformResourceIdentifier, eidasInfo.getOcspUri());
        accessDescriptions[1] = new AccessDescription(AccessDescription.id_ad_ocsp, oscpName);

        AuthorityInformationAccess authInfoAccess = new AuthorityInformationAccess(accessDescriptions);
        ASN1Primitive asn1Prim = authInfoAccess.toASN1Primitive();
        assertThat(AuthorityInformationAccess.getInstance(asn1Prim), is(authInfoAccess));
    }
}
