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
