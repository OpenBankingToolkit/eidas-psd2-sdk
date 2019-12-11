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

import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;


public class EidasCertTypeTest {

    @Test
    public void validateOIDs(){
        assertThat(EidasCertType.WEB.getOid(), is(ETSIQCObjectIdentifiers.id_etsi_qct_web.toString()));
        assertThat(EidasCertType.ESEAL.getOid(), is(ETSIQCObjectIdentifiers.id_etsi_qct_eseal.toString()));
        assertThat(EidasCertType.ESIGN.getOid(), is(ETSIQCObjectIdentifiers.id_etsi_qct_esign.toString()));
    }
}