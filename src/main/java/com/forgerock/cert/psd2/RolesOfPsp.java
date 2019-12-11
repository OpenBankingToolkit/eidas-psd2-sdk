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

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class RolesOfPsp extends ASN1Object {


    private Set<RoleOfPsp> roles = new HashSet<RoleOfPsp>();

    public RolesOfPsp(){
    }

    static RolesOfPsp getInstance(Object obj) throws InvalidPsd2EidasCertificate {
        if(obj instanceof RolesOfPsp){
            return (RolesOfPsp) obj;
        } else if (obj != null){
            try {
                ASN1Sequence asn1Seq = ASN1Sequence.getInstance(obj);
                return new RolesOfPsp(asn1Seq);
            } catch (IllegalArgumentException e){
                throw new InvalidPsd2EidasCertificate("Invalid argument to RolesOfPsp: " + obj.toString());
            }
        }
        return null;
    }

    private RolesOfPsp(ASN1Sequence seq) throws InvalidPsd2EidasCertificate {
        Enumeration e = seq.getObjects();
        int noInSeq = seq.size();
        for(int idx = 0; idx < noInSeq; ++idx){
            ASN1Encodable enc = seq.getObjectAt(idx);
            if(enc instanceof ASN1Sequence){
                ASN1Sequence roleSequence = (ASN1Sequence) enc;
                RoleOfPsp role = RoleOfPsp.getInstance(roleSequence);
                this.roles.add(role);
            } else {
                throw new InvalidPsd2EidasCertificate("Unexpected data in ASN2Sequence expected to contain roles. " +
                        "Seq: " + seq.toString());
            }

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

    @Override
    public String toString() {
        return "RolesOfPsp{" +
                "roles=" + roles +
                '}';
    }

    public Set<RoleOfPsp> getRolesOfPsp(){
        return this.roles;
    }
}
