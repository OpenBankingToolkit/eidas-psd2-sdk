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

import org.bouncycastle.asn1.*;

import java.io.IOException;

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

    public static Psd2QcStatement getInstance(Object obj){
        if(obj instanceof Psd2QcStatement){
            return (Psd2QcStatement) obj;
        } else if (obj != null){
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(obj);
                return new Psd2QcStatement(seq);
            } catch (IOException e){
                return null;
            }
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
     * @param seq
     * @throws IOException
     */
    private Psd2QcStatement(ASN1Sequence seq) throws IOException {

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
}