package com.forgerock.cert;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

class CertificateTestSpec {
    private String certName;
    private String filePath;
    private Boolean isPsd2Cert;

    public CertificateTestSpec(String certName, String filePath, Boolean isPsd2Cert) {
        this.certName = certName;
        this.filePath = filePath;
        this.isPsd2Cert = isPsd2Cert;
    }

    public X509Certificate[] getCert() throws IOException, CertificateException {
        return getCertFromFile(this.filePath);
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
