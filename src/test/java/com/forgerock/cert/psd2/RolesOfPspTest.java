/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.cert.psd2;

import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;


public class RolesOfPspTest {

    @Test
    public void serializeAndDeserialize(){
        RolesOfPsp roles = new RolesOfPsp();
        roles.addRole(Psd2Role.PSP_AI)
                .addRole(Psd2Role.PSP_AS);
        ASN1Primitive prim = roles.toASN1Primitive();

        RolesOfPsp deserialized = RolesOfPsp.getInstance(prim);
        assertThat(deserialized, is(roles));
    }
}