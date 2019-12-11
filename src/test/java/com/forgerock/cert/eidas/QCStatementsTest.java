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
package com.forgerock.cert.eidas;

import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.psd2.ASN1ObjectIdentifiers;
import com.forgerock.cert.psd2.Psd2QcStatement;
import com.forgerock.cert.psd2.Psd2Role;
import com.forgerock.cert.psd2.RolesOfPsp;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.hamcrest.CoreMatchers;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.util.Optional;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;


public class QCStatementsTest {

    @Test
    public void testSerializedAndDeserializedAreEqual() throws InvalidPsd2EidasCertificate, InvalidEidasCertType {
        QCStatements qcStatements = new QCStatements();
        qcStatements.addStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
        qcStatements.addStatement(ASN1ObjectIdentifiers.id_etsi_qcs_SemanticsId_Legal);
        EidasCertType eidasCertType = EidasCertType.ESIGN;
        ASN1ObjectIdentifier certTypeOid = new ASN1ObjectIdentifier(eidasCertType.getOid());
        DLSequence dlSequence = new DLSequence(certTypeOid);
        QCStatement certTypeStatement = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType,
                dlSequence);
        qcStatements.addStatement(certTypeStatement);

        // Create the PSD2 QCStatement
        // Add the roles.
        RolesOfPsp roles = new RolesOfPsp();
        roles.addRole(Psd2Role.PSP_AS);
        roles.addRole(Psd2Role.PSP_PI);

        String ncaName = "Test National Certificate Authority";
        String ncaId = "TEST-11111";

        Psd2QcStatement psd2QCStatement = new Psd2QcStatement(roles, ncaName, ncaId);
        qcStatements.setPsd2QcStatement(psd2QCStatement);


        // Serialize the data
        ASN1Primitive prim = qcStatements.toASN1Primitive();

        // Deserialize it
        Optional<QCStatements> deserializedOptional = QCStatements.getInstance(prim);
        assertThat(deserializedOptional.isPresent(), is(true));
        QCStatements deserialized = deserializedOptional.get();
        assertThat(deserialized.isEUQualifiedCert(), is(true));
        assertThat(deserialized.getEidasCertificateType().isPresent(), is(true));

        assertThat(deserialized.getEidasCertificateType().get(), is(eidasCertType));

        Optional<Psd2QcStatement> deserialisedPsd2StatmentOpt = deserialized.getPsd2QcStatement();
        assertThat(deserialisedPsd2StatmentOpt.isPresent(), is(true));
        assertThat(deserialisedPsd2StatmentOpt.get(), is(psd2QCStatement));

        assertThat(deserialized, is(qcStatements));
    }

    @Test
    public void testgetInstanceWithNullASN1() throws InvalidPsd2EidasCertificate {
        Optional<QCStatements> qcStatements = QCStatements.getInstance(null);
        assertThat(qcStatements.isPresent(), is(false));
    }

    @Test(expected=InvalidPsd2EidasCertificate.class)
    public void getInstanceWithBadASN1() throws InvalidPsd2EidasCertificate {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        DERUTF8String string = new DERUTF8String("Load of old tripe");
        vector.add(string);
        ASN1Sequence seq = ASN1Sequence.getInstance(new DERSequence(vector));
        assertThat(seq, CoreMatchers.is(notNullValue()));
        Optional<QCStatements> statements = QCStatements.getInstance(seq);
    }
}