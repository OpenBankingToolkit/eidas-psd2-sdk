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
    public void toASN1PrimAndBack() throws InvalidPsd2EidasCertificate {
        ASN1Primitive asn1Prim = qcStatement.toASN1Primitive();
        Psd2QcStatement fromASN1 = Psd2QcStatement.getInstance(asn1Prim);
        assertThat(fromASN1, is(this.qcStatement));
        assertThat(fromASN1.getRoles(), is((this.rolesOfPsp)));
    }

    @Test
    public void toDEREncodedAndBack() throws IOException, InvalidPsd2EidasCertificate {
        byte[] derEnc = this.qcStatement.getEncoded(ASN1Encoding.DER);

        ASN1InputStream aIn = new ASN1InputStream(derEnc);
        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        Psd2QcStatement deserialized = Psd2QcStatement.getInstance(seq);
        assertThat(deserialized, is(this.qcStatement));
        RolesOfPsp deserialisedRolesOfPsp = deserialized.getRoles();
        assertThat(deserialisedRolesOfPsp, is(this.rolesOfPsp));
    }
}