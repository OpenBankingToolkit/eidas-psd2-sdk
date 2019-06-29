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
package com.forgerock.cert.utils;

import com.forgerock.cert.eidas.EidasCertType;
import com.forgerock.cert.eidas.EidasInformation;
import com.forgerock.cert.eidas.QCStatements;
import com.forgerock.cert.psd2.ASN1ObjectIdentifiers;
import com.forgerock.cert.psd2.Psd2QcStatement;
import com.forgerock.cert.psd2.Psd2Role;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.exception.NoSuchRDNInField;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Set;
import javax.xml.bind.DatatypeConverter;


public class CertificateUtils {

    public static X509Certificate decodeCertificate(byte encodedCert[]) throws CertificateException {
        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(encodedCert);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)certFactory.generateCertificate(inputStream);
    }


    public static String generateB64EncodedSha1HashOfPublicKey(X509Certificate x509Cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = x509Cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
        return digestHex.toLowerCase();
    }


    public static PKCS10CertificationRequestBuilder addEidasExtensionsToCSR(PKCS10CertificationRequestBuilder csr,
                                                                            EidasCertType certType,
                                                                            EidasInformation eidasInfo)
            throws IOException {

        ExtensionsGenerator generator = new ExtensionsGenerator();

        //ToDo: what is the URI where a TPP can access the FR CA signing Cert?
        AccessDescription[] accessDescriptions = new AccessDescription[2];
        GeneralName caIssuerName = new GeneralName(GeneralName.uniformResourceIdentifier, eidasInfo.getCaIssuerCertURL());
        accessDescriptions[0] = new AccessDescription(AccessDescription.id_ad_caIssuers, caIssuerName);
        GeneralName oscpName = new GeneralName(GeneralName.uniformResourceIdentifier, eidasInfo.getOcspUri());
        accessDescriptions[1] = new AccessDescription(AccessDescription.id_ad_ocsp, oscpName);
        AuthorityInformationAccess authInfoAccess = new AuthorityInformationAccess(accessDescriptions);
        generator.addExtension(Extension.authorityInfoAccess, false, authInfoAccess);

        // Create the PSD2 QCStatement
        // Add the roles.
        RolesOfPsp roles = new RolesOfPsp();
        Set<Psd2Role> psd2Roles = eidasInfo.getPsd2Roles();
        for(Psd2Role psd2Role: psd2Roles){
            roles.addRole(psd2Role);
        }
        Psd2QcStatement psd2QCStatement = new Psd2QcStatement(roles, eidasInfo.getNcaName(), eidasInfo.getNcaId());

        // Add the eIDAS certificate extensions
        QCStatements qcStatements = new QCStatements();
        qcStatements.addStatement(ASN1ObjectIdentifiers.id_etsi_qcs_SemanticsId_Legal);
        qcStatements.addStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
        qcStatements.addStatement(new ASN1ObjectIdentifier(certType.getOid()));
        qcStatements.setPsd2QcStatement(psd2QCStatement);
        generator.addExtension(Extension.qCStatements, false, qcStatements.toASN1Primitive());

        Extensions extensions = generator.generate();

        csr.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);

        return csr;
    }

    public static X500Name getX500Name(CertificateConfiguration certConf){
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        String cn = certConf.getCn();
        if(!isEmpty(cn)){
            nameBuilder.addRDN(BCStyle.CN, cn);
        }

        String ou = certConf.getOu();
        if(!isEmpty(ou)){
            nameBuilder.addRDN(BCStyle.OU, ou);
        }

        String o = certConf.getO();
        if(!isEmpty(o)){
            nameBuilder.addRDN(BCStyle.O, o);
        }

        String l = certConf.getL();
        if(!isEmpty(l)){
            nameBuilder.addRDN(BCStyle.L, l);
        }

        String st = certConf.getSt();
        if(!isEmpty(st)){
            nameBuilder.addRDN(BCStyle.ST, st);
        }

        String c = certConf.getC();
        if(!isEmpty(c)){
            nameBuilder.addRDN(BCStyle.C, c);
        }

        String oi = certConf.getOi();
        if(!isEmpty(oi)){
            nameBuilder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, oi);
        }

        return nameBuilder.build();
    }

    public static String getOrganisationIdentifier(X509Certificate cert) throws CertificateEncodingException,
            InvalidPsd2EidasCertificate {
        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        return CertificateUtils.getOrganisationIdentifier(certHolder);
    }

    public static String getOrganisationIdentifier(JcaX509CertificateHolder certHolder )
            throws InvalidPsd2EidasCertificate {
        X500Name subject = certHolder.getSubject();
        if(subject == null){
            throw new InvalidPsd2EidasCertificate("Certificate has no subject");
        }

        RDN[] rdns = subject.getRDNs(BCStyle.ORGANIZATION_IDENTIFIER);
        if(rdns == null || rdns.length == 0){
            rdns = subject.getRDNs(BCStyle.OU);
        }

        if(rdns == null || rdns.length == 0){
            throw new InvalidPsd2EidasCertificate("No Organization Identifier in certificate. Expected an " +
                    "organization ID in the subject RDN with OID of " + BCStyle.ORGANIZATION_IDENTIFIER.getId() +
                    " Format should follow the id-etsi-qcs-SemanticsId-Legal format as described in section 5.1.4 of " +
                    " ETSI TS 119 412-1 V1.2.1 (2018-05). Link: " +
                    "https://www.etsi.org/deliver/etsi_ts/119400_119499/11941201/01.02.01_60/ts_11941201v010201p.pdf");
        }

        RDN rdn = rdns[0];
        String errorMessage = "";
        if(rdn != null){
            AttributeTypeAndValue attributeTypeAndValue = rdn.getFirst();
            if(attributeTypeAndValue != null){
                ASN1Encodable attributeValue = attributeTypeAndValue.getValue();
                if(attributeValue != null){
                    return IETFUtils.valueToString(attributeValue);
                } else {
                    errorMessage = "Malformed Organization Identifier - attribute type and value was null, rdn was " + rdn;
                }
            } else {
                errorMessage = "Malformed Organization Identifier - rdn was null, rdns was " + Arrays.toString(rdns);
            }
        } else {
            errorMessage = "Malformed Organization Identifier - rdn was null";
        }
        throw new InvalidPsd2EidasCertificate("Malformed Organization Identifier in certificate. Expected an " +
                "organization ID in the subject RDN with OID of " + BCStyle.ORGANIZATION_IDENTIFIER.getId() +
                " Format should follow the id-etsi-qcs-SemanticsId-Legal format as described in section 5.1.4 of " +
                " ETSI TS 119 412-1 V1.2.1 (2018-05). Link: " +
                "https://www.etsi.org/deliver/etsi_ts/119400_119499/11941201/01.02.01_60/ts_11941201v010201p.pdf. " +
                "Error details: " + errorMessage

        );
    }


    public static String getRDNAsString(X509Certificate cert, RdnField field, ASN1ObjectIdentifier rdnOid)
            throws CertificateEncodingException, NoSuchRDNInField {
        JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
        X500Name name;

        switch(field){
            case ISSUER:
                name = holder.getIssuer();
                break;
            case SUBJECT:
                name = holder.getSubject();
                break;
            default:
                throw new IllegalArgumentException("Unrecognised RdnField value: " + field.toString());
        }

        if(name == null) {
            throw new NoSuchRDNInField("Certificate has no '" + field.toString() + "' field");
        }

        RDN[] rdns = name.getRDNs(rdnOid);
        if(rdns == null | rdns.length == 0){
            String msg = MessageFormat.format("RDN '{0}' not found in certificate field '{1}'",
                    field.toString(), rdnOid.getId());
            throw new NoSuchRDNInField(msg);
        }

        RDN rdn = rdns[0];
        if(rdn != null){
            AttributeTypeAndValue attributeTypeAndValue = rdn.getFirst();
            if(attributeTypeAndValue != null){
                ASN1Encodable attributeValue = attributeTypeAndValue.getValue();
                if(attributeValue != null){
                    String value =  IETFUtils.valueToString(attributeValue);
                    if(!isEmpty(value)){
                        return value;
                    }
                }
            }
        }
        String errMsg = MessageFormat.format("Malformed RDN '{}' in field '{}': {}", rdnOid.getId(), field,
                rdn.toString() );
        throw new NoSuchRDNInField(errMsg);
    }
    
    private static boolean isEmpty(String value) {
        return value == null || "".equals(value);
    }
}
