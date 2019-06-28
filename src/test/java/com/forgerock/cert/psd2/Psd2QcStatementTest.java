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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;


public class Psd2QcStatementTest {


    private RolesOfPsp rolesOfPsp = new RolesOfPsp();
    private String ncaId = "AV-11111";
    private String ncaName = "Avalon Certification Authority Ltd";
    private Psd2QcStatement qcStatement = new Psd2QcStatement(this.rolesOfPsp, this.ncaName, this.ncaId);

    @Before
    public void initialize(){
        this.rolesOfPsp.addRole(Psd2Role.PSP_AI);
    }

    @Test
    public void toASN1PrimAndBack(){
        ASN1Primitive asn1Prim = qcStatement.toASN1Primitive();
        Psd2QcStatement fromASN1 = Psd2QcStatement.getInstance(asn1Prim);
        assertThat(fromASN1, is(this.qcStatement));
        assertThat(fromASN1.getRoles(), is((this.rolesOfPsp)));
    }

    @Test
    public void toDEREncodedAndBack() throws IOException {
        byte[] derEnc = this.qcStatement.getEncoded(ASN1Encoding.DER);

        ASN1InputStream aIn = new ASN1InputStream(derEnc);
        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        Psd2QcStatement deserialized = Psd2QcStatement.getInstance(seq);
        assertThat(deserialized, is(this.qcStatement));
        RolesOfPsp deserialisedRolesOfPsp = deserialized.getRoles();
        assertThat(deserialisedRolesOfPsp, is(this.rolesOfPsp));
    }
}