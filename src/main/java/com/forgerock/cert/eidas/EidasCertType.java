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

/**
 * An enum that also ties the ASN.1 oid to the type for use when creating
 * certificates. Types expected in the QC-STATEMENT in a compliant eIDAS
 * cert are specified in
 * {@link "https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.00.12_20/en_31941205v020012a.pdf"}
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
