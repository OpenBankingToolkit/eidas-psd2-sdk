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
package com.forgerock.cert.psd2;

import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.hamcrest.CoreMatchers;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;


public class RolesOfPspTest {

    @Test
    public void serializeAndDeserialize() throws InvalidPsd2EidasCertificate {
        RolesOfPsp roles = new RolesOfPsp();
        roles.addRole(Psd2Role.PSP_AI)
                .addRole(Psd2Role.PSP_AS);
        ASN1Primitive prim = roles.toASN1Primitive();

        RolesOfPsp deserialized = RolesOfPsp.getInstance(prim);
        assertThat(deserialized, is(roles));
    }

    @Test
    public void testWithEmptySequence() throws InvalidPsd2EidasCertificate {
        DERUTF8String str = new DERUTF8String("Nonsense");
        ASN1EncodableVector roleVector = new ASN1EncodableVector();
        DERSequence derSeq = new DERSequence(roleVector);
        RolesOfPsp rolesOfPsp = RolesOfPsp.getInstance(derSeq);
        assertThat(rolesOfPsp,  CoreMatchers.is(notNullValue()));
    }

    @Test(expected=InvalidPsd2EidasCertificate.class)
    public void testWithInvalidDataInSequence() throws InvalidPsd2EidasCertificate {
        DERUTF8String str = new DERUTF8String("Nonsense");
        ASN1EncodableVector roleVector = new ASN1EncodableVector();
        roleVector.add(str);
        DERSequence derSeq = new DERSequence(roleVector);
        RolesOfPsp rolesOfPsp = RolesOfPsp.getInstance(derSeq);
        assertThat(rolesOfPsp,  CoreMatchers.is(notNullValue()));
    }
}