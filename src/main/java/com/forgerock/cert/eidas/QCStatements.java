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

import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.psd2.Psd2QcStatement;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import java.io.IOException;
import java.util.*;


public class QCStatements extends ASN1Object {

    Map<String, QCStatement> qcStatements = new TreeMap<>();

    public QCStatements(){}

    public static ASN1ObjectIdentifier getOid(){
        return Extension.qCStatements;
    }

    public static Optional<QCStatements> getInstance(Object obj) throws InvalidPsd2EidasCertificate {
        if(obj instanceof QCStatements){
            Optional.of((QCStatements)obj);
        } else if (obj != null){
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(obj);
                return Optional.of(new QCStatements(seq));
            } catch (IllegalArgumentException  e){
                throw new InvalidPsd2EidasCertificate("Exception creating the QCStatements : " + obj, e);
            }
        }
        return Optional.empty();
    }

    /**
     *
     * @param seq A sequence containing the oid of the X509 QCStatements type and another sequence containing
     *            all of the QCStatements
     * @throws IOException
     */
    private QCStatements(ASN1Sequence seq) throws InvalidPsd2EidasCertificate {

        if (seq.size() < 1){
            throw new IllegalArgumentException("sequence may not be empty");
        }

        Enumeration asn1QcStatements = seq.getObjects();
        // Iterate across the statements
        while(asn1QcStatements.hasMoreElements()){

            try {
                // So a statement should be in a sequence containing OID and optional extra stuff.
                ASN1Sequence itemSeq = ASN1Sequence.getInstance(asn1QcStatements.nextElement());
                Enumeration innerEnum = itemSeq.getObjects();

                // Get the first element of the sequence. This will be the oid that will identify the
                // type of QCStatement.
                ASN1Encodable firstItem = (ASN1Encodable) innerEnum.nextElement();
                if (firstItem instanceof ASN1ObjectIdentifier) {
                    ASN1ObjectIdentifier itemOid = ASN1ObjectIdentifier.getInstance(firstItem);
                    QCStatement qcItem = null;
                    if (innerEnum.hasMoreElements()) {
                        ASN1Encodable furtherInfo = (ASN1Encodable) innerEnum.nextElement();
                        qcItem = new QCStatement(itemOid, furtherInfo);
                    } else {
                        qcItem = new QCStatement(itemOid);
                    }
                    this.qcStatements.put(itemOid.getId(), qcItem);
                } else {
                    throw new InvalidPsd2EidasCertificate("No ASN1ObjectIdentifier in Sequence");
                }
            } catch (IllegalArgumentException e){
                throw new InvalidPsd2EidasCertificate("Could not create QCStatements from ASN1Sequence", e);
            }
        }
    }

    public static Optional<QCStatements> fromExtensions(Extensions extensions) throws InvalidPsd2EidasCertificate {
        ASN1Encodable encodable = extensions.getExtensionParsedValue(Extension.qCStatements);
        return QCStatements.getInstance(encodable);
    }

    /**
     * Adds a QC Statement to the list of statements
     * @param id - the Object Identifier of the statement being added.
     */
    public void addStatement(ASN1ObjectIdentifier id) {
        QCStatement qcStatement = new QCStatement(id);
        qcStatements.put(id.getId(), qcStatement);
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector inner = new ASN1EncodableVector();
        for(QCStatement statement: qcStatements.values()){
            inner.add(statement.toASN1Primitive());
        }
        return new DERSequence(inner);
    }

    public boolean isEUQualifiedCert() {
        return this.qcStatements.containsKey(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId());
    }

    public void setEidasCertificateType(EidasCertType esign) {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(esign.getOid());
        QCStatement qcStatement = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, oid);
        this.qcStatements.put(oid.getId(), qcStatement);
    }

    public Optional<EidasCertType> getEidasCertificateType() throws InvalidEidasCertType {
        return Arrays.asList(EidasCertType.values()).stream().filter(t -> this.qcStatements.containsKey(t.getOid())).findAny();
    }

    public void setPsd2QcStatement(Psd2QcStatement psd2QCStatement) {
        QCStatement qcStatement = new QCStatement(Psd2QcStatement.getOid(), psd2QCStatement.toASN1Primitive());
        this.qcStatements.put(Psd2QcStatement.getOid().getId(), qcStatement);
    }

    public Optional<Psd2QcStatement> getPsd2QcStatement() throws InvalidPsd2EidasCertificate {
        QCStatement qcStatement = this.qcStatements.get(Psd2QcStatement.getOid().getId());
        return Optional.ofNullable(Psd2QcStatement.getInstance(qcStatement.getStatementInfo()));
    }

    public Optional<QCStatement> getQCStatement(ASN1ObjectIdentifier oid) {
        return Optional.ofNullable(this.qcStatements.get(oid.getId()));
    }

    @Override
    public String toString() {
        return "QCStatements{" +
                "qcStatements=" + qcStatements +
                '}';
    }
}