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

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class RolesOfPsp extends ASN1Object {

    private Set<RoleOfPsp> roles = new HashSet<RoleOfPsp>();

    public RolesOfPsp(Set<RoleOfPsp> roles){
        this.roles = roles;
    }

    public RolesOfPsp(){
    }

    static RolesOfPsp getInstance(Object obj){
        if(obj instanceof RolesOfPsp){
            return (RolesOfPsp) obj;
        } else if (obj != null){
            return new RolesOfPsp(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private RolesOfPsp(ASN1Sequence seq){
        Enumeration e = seq.getObjects();

        // qcstatementInfo
        while (e.hasMoreElements())
        {
            ASN1Sequence roleSequence = (ASN1Sequence) e.nextElement();
            RoleOfPsp role = RoleOfPsp.getInstance(roleSequence);
            this.roles.add(role);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector roleVector = new ASN1EncodableVector();
        roles.forEach((s)->{
            roleVector.add(s.toASN1Primitive());
        });

        return new DERSequence(roleVector);
    }

    public RolesOfPsp addRole(Psd2Role psd2Role) {
        roles.add(new RoleOfPsp(psd2Role));
        return this;
    }
}
