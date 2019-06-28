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