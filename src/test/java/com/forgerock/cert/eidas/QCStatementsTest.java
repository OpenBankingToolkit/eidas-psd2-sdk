/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
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
import org.junit.Test;

import java.io.IOException;
import java.util.Optional;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;


public class QCStatementsTest {

    @Test
    public void testSerializedAndDeserializedAreEqual() throws IOException, InvalidEidasCertType, InvalidPsd2EidasCertificate {
        QCStatements qcStatements = new QCStatements();
        qcStatements.addStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
        qcStatements.addStatement(ASN1ObjectIdentifiers.id_etsi_qcs_SemanticsId_Legal);
        EidasCertType eidasCertType = EidasCertType.ESIGN;
        qcStatements.setEidasCertificateType(eidasCertType);

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
        assertThat(deserialized.getEidasCertificateType(), is(eidasCertType));

        Psd2QcStatement deserialisedPsd2Statment = deserialized.getPsd2QcStatement();
        assertThat(deserialisedPsd2Statment, is(psd2QCStatement));

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
        assertThat(seq, not(null));
        Optional<QCStatements> statements = QCStatements.getInstance(seq);
    }
}