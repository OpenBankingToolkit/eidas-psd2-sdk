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

/**
 *
 * ASN.1 definition
 * ****************
 *
 * RoleOfPSP ::= SEQUENCE{
 *  roleOfPspOid RoleOfPspOid,
 *  roleOfPspName RoleOfPspName }
 * RoleOfPspOid ::= OBJECT IDENTIFIER
 * -- Object Identifier arc for roles of payment service providers
 * -- defined in the present document
 * etsi-psd2-roles OBJECT IDENTIFIER ::=
 * { itu-t(0) identified-organization(4) etsi(0) psd2(19495) id-roles(1) }
 *
 * -- Account Servicing Payment Service Provider (PSP_AS) role
 * id-psd2-role-psp-as OBJECT IDENTIFIER ::=
 * { itu-t(0) identified-organization(4) etsi(0) psd2(19495) id-roles(1) 1 }
 * -- Payment Initiation Service Provider (PSP_PI) role
 * id-psd2-role-psp-pi OBJECT IDENTIFIER ::=
 * { itu-t(0) identified-organization(4) etsi(0) psd2(19495) id-roles(1) 2 }
 *
 * -- Account Information Service Provider (PSP_AI) role
 * id-psd2-role-psp-ai OBJECT IDENTIFIER ::=
 * { itu-t(0) identified-organization(4) etsi(0) psd2(19495) id-roles(1) 3 }
 * -- Payment Service Provider issuing card-based payment instruments (PSP_IC) role
 * id-psd2-role-psp-ic OBJECT IDENTIFIER ::=
 * { itu-t(0) identified-organization(4) etsi(0) psd2(19495) id-roles(1) 4 }
 * -- Payment Service Provider role name corresponding with OID (i.e. PSP_AS,
 * -- PSP_PI, PSP_AI, PSP_IC)
 * RoleOfPspName ::= UTF8String (SIZE(1..256))
 */
public class RoleOfPsp extends ASN1Object {

    private Psd2Role role;

    public static RoleOfPsp getInstance(Object obj){
        if(obj instanceof RoleOfPsp){
            return (RoleOfPsp) obj;
        } else if (obj != null){
            return new RoleOfPsp(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private RoleOfPsp(ASN1Sequence seq){
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        String oidString = oid.toString();
        for(Psd2Role role : Psd2Role.values()){
            if(oidString.equals(role.getOid())){
                this.role = role;
            }
        }
    }

    public RoleOfPsp(Psd2Role role){
        this.role = role;
        // This might throw so check it here on construction rather than when required later
        // as this might aid debugging should things go wrong.
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(role.getOid());
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(role.getOid());
        v.add(oid);
        v.add(new DERUTF8String(this.role.getRoleName()));
        return new DERSequence(v);
    }
}
