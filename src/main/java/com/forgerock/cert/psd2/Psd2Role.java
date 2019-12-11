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

/**
 * And enum class used to specify PSD2 TPP roles.
 * This enum ties the roles to the OID's specified for those
 * roles in the following ETSI document;
 * <a href="https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.01.02_60/ts_119495v010102p.pdf"></a>
 */
public enum Psd2Role {
    PSP_AS ("0.4.0.19495.1.1", "Account Servicing"),
    PSP_PI("0.4.0.19495.1.2", "Payment Initiation"),
    PSP_AI("0.4.0.19495.1.3", "Account Information"),
    PSP_IC("0.4.0.19495.1.4", "Card Based Payment Instruments");

    private final String oid;
    private final String roleName;

    /**
     * Constructor used by the enum Value definitions above
     * @param oid this ASN.1 OID of the PSD2 role as defined in the ETSI doc ref'd. in the
     *            class javadoc.
     * @param roleName a human readable name for the role.
     */
    private Psd2Role(String oid, String roleName){
        this.oid = oid;
        this.roleName = roleName;
    }

    /**
     * Get the ASN.1 Object Id associated with the PSD2 role
     * @return The string representation of the ASN.1 Object Identifiier.
     */
    public String getOid() {
        return oid;
    }

    /**
     * Returns a role name for the role (used for descriptions etc)
     * @return the role name
     */
    public String getRoleName() {
        return roleName;
    }
}
