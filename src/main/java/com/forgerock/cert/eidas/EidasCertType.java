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

/**
 * An enum that also ties the ASN.1 oid to the type for use when creating
 * certificates. Types expected in the QC-STATEMENT in a compliant eIDAS
 * cert are specified in
 * <a href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.00.12_20/en_31941205v020012a.pdf"></a>
 *
 * The types are;
 *  <pre>
 *  -- QC type identifiers
 *  id-etsi-qct-esign OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 1 }
 *  -- Certificate for electronic signatures as defined in Regulation (EU) No 910/2014
 *  id-etsi-qct-eseal OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 2 }
 *  -- Certificate for electronic seals as defined in Regulation (EU) No 910/2014
 *  id-etsi-qct-web OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 3 }
 *  -- Certificate for website authentication as defined in Regulation (EU) No 910/2014
 *  </pre>
 */
public enum EidasCertType {
    /**
     * ESIGN - A Certificate for electronic signatures as defined in Regulation (EU) No 910/2014
     */
    ESIGN("0.4.0.1862.1.6.1")
    ,
    /**
     * ESEAL - A Certificate for electronic seals as defined in Regulation (EU) No 910/2014
     */
    ESEAL("0.4.0.1862.1.6.2"),

    /**
     * Certificate for website authentication as defined in Regulation (EU) No 910/2014
     */
    WEB("0.4.0.1862.1.6.3");


    // The ASN.1 Object Identifier.
    private String oid;

    EidasCertType(String oid){
        this.oid = oid;
    }

    public static EidasCertType getInstance(String oid) throws InvalidEidasCertType {
        for(EidasCertType value: EidasCertType.values()){
            if(oid.equals(value.getOid())){
                return value;
            }
        }
        throw new InvalidEidasCertType("Unrecognised Object Identifier " + oid);
    }

    /**
     * Get the ASN.1 Object Identifier for this eIDAS certificate type as it appears in the
     * QC-STATEMENT defined in the doc linked in the enum level docs
     * @return the Object Identifier in a dot separated format.
     */
    public String getOid() {
        return oid;
    }
}
