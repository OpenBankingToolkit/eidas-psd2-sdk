/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.cert.eidas;

import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;


public class EidasCertTypeTest {

    @Test
    public void validateOIDs(){
        assertThat(EidasCertType.WEB.getOid(), is(ETSIQCObjectIdentifiers.id_etsi_qct_web.toString()));
        assertThat(EidasCertType.ESEAL.getOid(), is(ETSIQCObjectIdentifiers.id_etsi_qct_eseal.toString()));
        assertThat(EidasCertType.ESIGN.getOid(), is(ETSIQCObjectIdentifiers.id_etsi_qct_esign.toString()));
    }
}