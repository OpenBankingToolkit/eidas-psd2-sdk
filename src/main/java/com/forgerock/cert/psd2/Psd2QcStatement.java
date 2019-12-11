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
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import java.io.IOException;
import java.util.Optional;

public class Psd2QcStatement extends ASN1Object {

    private static ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("0.4.0.19495.2");
    private RolesOfPsp roles;
    private String ncaName;
    private String ncaId;

    public Psd2QcStatement(RolesOfPsp rolesOfPsp, String ncaName, String ncaId){
        this.roles = rolesOfPsp;
        this.ncaName = ncaName;
        this.ncaId = ncaId;
    }

    /**
     * Obtain a Psd2QcStatement object from an eidas certificate if it contains one.
     * @param extensions extensions
     * @return Returns an Optional Psd2QcStatement. If the certificate did not contain a Psd2 QcStatement then it will
     * be empty, if not it will contain the Psd2QcStatement
     * @throws InvalidPsd2EidasCertificate If the contents of the ASN1 in the extension does not conform to the expected
     * Schema
     */
    public static Optional<Psd2QcStatement> fromExtensions(Extensions extensions) throws InvalidPsd2EidasCertificate {
        Extension extension = extensions.getExtension(Psd2QcStatement.getOid());
        if(extension != null){
            return Optional.of(Psd2QcStatement.getInstance(extension.getParsedValue()));
        }
        return Optional.empty();
    }

    public static Psd2QcStatement getInstance(Object obj) throws InvalidPsd2EidasCertificate {
        if(obj instanceof Psd2QcStatement){
            return (Psd2QcStatement) obj;
        } else if (obj != null){
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);
            return new Psd2QcStatement(seq);
        }
        return null;
    }

    public static ASN1ObjectIdentifier getOid(){
        return Psd2QcStatement.oid;
    }

    /**
     * Here we expect the following ASN1
     * SEQUENCE {                                                     -- seq
     *     SEQUENCE {                                                 -- rolesSeq
     *         SEQUENCE {                                             -- roleSeq
     *             OBJECT IDENTIIFIER -- of PSD2 Role
     *             DERUTF8String -- Role of PSD2 Name
     *         }
     *         SEQUENCE {
     *             OBJECT IDENTIFIER -- of other PSD2 Roles... etc
     *             DERUTF8String -- Role of PSD2 Name
     *         }
     *     }
     *     DERUTF8String NCAName
     *     DERUTF8String NCAId
     * }
     * @param seq sequence
     * @throws IOException
     */
    private Psd2QcStatement(ASN1Sequence seq) throws InvalidPsd2EidasCertificate {

        ASN1Sequence rolesSeq = (ASN1Sequence) seq.getObjectAt(0);
        this.roles = RolesOfPsp.getInstance(rolesSeq);
        this.ncaName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.ncaId = DERUTF8String.getInstance(seq.getObjectAt(2)).getString();
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector inner = new ASN1EncodableVector();
        inner.add(this.roles.toASN1Primitive());
        inner.add(new DERUTF8String(this.ncaName));
        inner.add(new DERUTF8String(this.ncaId));
        return new DERSequence(inner);
    }

    public RolesOfPsp getRoles() {
        return roles;
    }

    public String getNcaName() { return this.ncaName; };

    public String getNcaId() { return this.ncaId; }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Psd2QcStatement{");
        sb.append("ncaName='" + ncaName + '\'');
        sb.append(", ncaId='" + ncaId + '\'');
        sb.append(", roles='" + roles + '\'');
        sb.append('}');
        return sb.toString();
    }
}