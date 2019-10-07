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
import com.forgerock.cert.eidas.QCStatements;
import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.exception.NoSuchRDNInField;
import com.forgerock.cert.psd2.Psd2QcStatement;
import com.forgerock.cert.utils.CertificateUtils;
import com.forgerock.cert.utils.RdnField;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
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
    private Psd2QcStatement psd2QcStatement;
    private EidasCertType eidasCertType;

    public Psd2CertInfo(X509Certificate[] cert) throws InvalidPsd2EidasCertificate {
        this(Arrays.asList(cert));
    }

    public Psd2CertInfo(List<X509Certificate> certs) throws InvalidPsd2EidasCertificate {
        JcaX509CertificateHolder certHolder;
        try {
            certHolder = new JcaX509CertificateHolder(certs.get(0));
        } catch (CertificateEncodingException e){
            throw new InvalidPsd2EidasCertificate("Failed to understand certificate ", e);
        }

        this.certs = certs;
        Extensions extensions = certHolder.getExtensions();
        if (extensions != null) {
            Optional<QCStatements> qcStatementsOpt = QCStatements.fromExtensions(extensions);
            if(qcStatementsOpt.isPresent()){
                this.qcStatements = qcStatementsOpt.get();
                Optional<Psd2QcStatement> psd2QcStatementOpt = this.qcStatements.getPsd2QcStatement();
                if(psd2QcStatementOpt.isPresent()){
                    this.psd2QcStatement = psd2QcStatementOpt.get();
                }
            }

            this.authorityInfoAccess = AuthorityInformationAccess.fromExtensions(extensions);
            this.organizationId = CertificateUtils.getOrganisationIdentifier(certHolder);

        }
    }

    public Boolean isPsd2Cert() {

        // This line is more correct. However, OB certificates do not add the etsi qualified cert statement to their
        // eidas certificates, so we need to look to see if the qcType is set.
        // boolean isPsd2Cert =  (this.qcStatements != null && this.qcStatements.isEUQualifiedCert()
        //        && this.psd2QcStatement != null);
        boolean isPsd2Cert = false;
        try {
            isPsd2Cert = (this.qcStatements != null && this.qcStatements.getEidasCertificateType().isPresent()
                    && this.psd2QcStatement != null);
        } catch (InvalidEidasCertType invalidCertType){
            isPsd2Cert = false;
        }
        return isPsd2Cert;
    }

    public Optional<String> getAuthorityAccessInfoCAIssuer(){
        if(getAuthorityAccessInfo().isPresent()){
            AuthorityInformationAccess authInfoAccess =  getAuthorityAccessInfo().get();
            AccessDescription[] accessDescriptions = authInfoAccess.getAccessDescriptions();
            for(int i = 0; i < accessDescriptions.length; ++i){
                AccessDescription accessDescription = accessDescriptions[i];
                if(accessDescription != null){
                    if(accessDescription.getAccessMethod().getId().equals(AccessDescription.id_ad_caIssuers.getId())){
                        GeneralName generalName = accessDescription.getAccessLocation();
                        ASN1Encodable gName = generalName.getName();
                        ASN1String name = (ASN1String)gName;
                        return Optional.of(name.getString());
                    }
                }
            }
        }
        return Optional.empty();
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

    public Optional<EidasCertType> getEidasCertType() throws InvalidEidasCertType {
       return qcStatements.getEidasCertificateType();
    }


    public Optional<String> getOrganizationId(){
        return Optional.ofNullable(this.organizationId);
    }

    public String getApplicationId() throws NoSuchRDNInField, CertificateEncodingException {
        X509Certificate appCert = this.certs.get(0);
        return CertificateUtils.getRDNAsString(appCert, RdnField.SUBJECT, BCStyle.CN);
    }

    public Optional<Psd2QcStatement> getPsd2QCStatement() throws InvalidPsd2EidasCertificate {
        return Optional.ofNullable(this.psd2QcStatement);
    }


    @Override
    public String toString() {
        String LINE_SEP =  System.getProperty("line.separator");
        StringBuilder sb = new StringBuilder("Psd2Cert: ");
        if(isPsd2Cert()){
            sb.append("OrganizationId is '").append(this.organizationId).append("'").append(LINE_SEP);
            sb.append("Subject is: ").append(this.certs.get(0).getSubjectDN().getName()).append(LINE_SEP);
            sb.append("Psd2Statements: ").append(this.psd2QcStatement.toString()).append(LINE_SEP);
            sb.append("QCStatements: ").append(this.qcStatements.toString()).append(LINE_SEP);
        } else {
            sb.append("Constructed from non PSD2 certificate");
        }
        return sb.toString();
    }
}
