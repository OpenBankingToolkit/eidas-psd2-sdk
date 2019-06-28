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
