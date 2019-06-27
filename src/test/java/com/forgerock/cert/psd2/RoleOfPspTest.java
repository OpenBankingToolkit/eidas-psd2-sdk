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


public class RoleOfPspTest {

    @Test
    public void serializeAndDeserialize(){
        RoleOfPsp role = new RoleOfPsp(Psd2Role.PSP_AI);
        ASN1Primitive serialized = role.toASN1Primitive();

        RoleOfPsp deserialized = RoleOfPsp.getInstance(serialized);
        assertThat(deserialized, is(serialized));
    }

}