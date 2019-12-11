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
package com.forgerock.cert;

import com.forgerock.cert.eidas.EidasCertType;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

class CertificateTestSpec {
    private String certName;
    private String filePath;
    private Boolean isPsd2Cert;
    private EidasCertType eidasCertType;

    public CertificateTestSpec(String certName, String filePath, Boolean isPsd2Cert, EidasCertType eidasCertType) {
        this.certName = certName;
        this.filePath = filePath;
        this.isPsd2Cert = isPsd2Cert;
        this.eidasCertType = eidasCertType;
    }

    public X509Certificate[] getCert() throws IOException, CertificateException {
        return getCertFromFile(this.filePath);
    }

    public EidasCertType getEidasCertType() {
        return eidasCertType;
    }

    private X509Certificate[] getCertFromFile(String path) throws IOException, CertificateException {
        FileInputStream fis = null;
        try{
            fis = new FileInputStream(path);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return new X509Certificate[]{(X509Certificate) certificateFactory.generateCertificate(fis)};
        } finally {
            if(fis != null) fis.close();
        }
    }

    public Boolean isPsd2Cert() {
        return isPsd2Cert;
    }
}
