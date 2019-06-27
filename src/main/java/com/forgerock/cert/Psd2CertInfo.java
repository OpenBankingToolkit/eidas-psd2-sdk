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

import com.forgerock.cert.eidas.QCStatements;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.exception.NoSuchRDNInField;
import com.forgerock.cert.utils.CertificateUtils;
import com.forgerock.cert.utils.RdnField;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Gets the PSD2 information from a X509Certificate
 */
public class Psd2CertInfo {
    private QCStatements qcStatements;
    private AuthorityInformationAccess authorityInfoAccess = null;
    private String organizationId;
    private List<X509Certificate> certs;

    public Psd2CertInfo(X509Certificate[] cert) throws CertificateEncodingException, InvalidPsd2EidasCertificate {
        this(Arrays.asList(cert));
    }

    public Psd2CertInfo(List<X509Certificate> certs) throws CertificateEncodingException, InvalidPsd2EidasCertificate {
        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(certs.get(0));
        this.certs = certs;
        Extensions extensions = certHolder.getExtensions();
        if (extensions != null) {
            Optional<QCStatements> qcStatementsOpt = QCStatements.fromExtensions(extensions);
            if(qcStatementsOpt.isPresent()){
                this.qcStatements = qcStatementsOpt.get();
            }
            this.authorityInfoAccess = AuthorityInformationAccess.fromExtensions(extensions);
            this.organizationId = CertificateUtils.getOrganisationIdentifier(certs.get(0));
        }
    }

    public Boolean isPsd2Cert(){
        return (this.qcStatements != null && this.qcStatements.isEUQualifiedCert()
                && this.qcStatements.getPsd2QcStatement() != null);
    }

    public Optional<AuthorityInformationAccess> getAuthorityAccessInfo() {
        return Optional.ofNullable(this.authorityInfoAccess);
    }

    public Optional<QCStatement> getQCStatement(ASN1ObjectIdentifier oid) {
        if(this.qcStatements != null){
            return this.qcStatements.getQCStatement(oid);
        }
        return Optional.empty();
    }

    public Optional<String> getOrganizationId(){
        return Optional.ofNullable(this.organizationId);
    }

    public String getApplicationId() throws NoSuchRDNInField, CertificateEncodingException {
        X509Certificate appCert = this.certs.get(0);
        return CertificateUtils.getRDNAsString(appCert, RdnField.SUBJECT, BCStyle.CN);
    }
}
