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

import com.forgerock.cert.psd2.Psd2Role;

import java.util.HashSet;
import java.util.Set;

/**
 * Information required to create an eIDAS Qualified seals and certs.
 * The spec defining what should be included in an eIDAS cert is Regulation (EU) No 910/2014 - which may be found
 * in <a href="https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32014R0910&from=EN"></a>
 *
 * ====================================================================================================================
 * As of 19/10/2018 the following spec applies;
 * <pre>
 * REQUIREMENTS FOR QUALIFIED CERTIFICATES FOR WEBSITE AUTHENTICATION
 *
 * Qualified certificates for website authentication shall contain:
 *
 * (a) an indication, at least in a form suitable for automated processing, that the certificate has been issued as a
 *     qualified certificate for website authentication;
 * (b) a set of data unambiguously representing the qualified trust service provider issuing the qualified certificates
 *     including at least the Member State in which that provider is established and:
 *     —for a legal person: the name and, where applicable, registration number as stated in the official records,
 *     —for a natural person: the person’s name;
 * (c) for natural persons: at least the name of the person to whom the certificate has been issued, or a pseudonym.
 *     If a pseudonym is used, it shall be clearly indicated;
 *     — for legal persons: at least the name of the legal person to whom the certificate is issued and,
 *       where applicable, registration number as stated in the official records;
 * (d) elements of the address, including at least city and State, of the natural or legal person to whom the
 *     certificate is issued and, where applicable, as stated in the official records;
 * (e) the domain name(s) operated by the natural or legal person to whom the certificate is issued;
 * (f) details of the beginning and end of the certificate’s period of validity;
 * (g) the certificate identity code, which must be unique for the qualified trust service provider;
 * (h) the advanced electronic signature or advanced electronic seal of the issuing qualified trust service provider;
 * (i) the location where the certificate supporting the advanced electronic signature or advanced electronic seal
 *     referred to in point (h) is available free of charge;
 * (j) the location of the certificate validity status services that can be used to enquire as to the validity status
 *     of the qualified certificate.
 *
 * REQUIREMENTS FOR QUALIFIED CERTIFICATES FOR ELECTRONIC SEALS
 *
 * Qualified certificates for electronic seals shall contain:
 * (a) an indication, at least in a form suitable for automated processing, that the certificate has been issued as a
 *     qualified certificate for electronic seal;
 * (b) a set of data unambiguously representing the qualified trust service provider issuing the qualified certificates
 *     including at least the Member State in which that provider is established and:
 *     — for a legal person: the name and, where applicable, registration number as stated in the official records,
 *     — for a natural person: the person’s name;
 * (c) at least the name of the creator of the seal and, where applicable, registration number as stated in the official
 *     records;
 * (d) electronic seal validation data, which corresponds to the electronic seal creation data;
 * (e) details of the beginning and end of the certificate’s period of validity;
 * (f) the certificate identity code, which must be unique for the qualified trust service provider;
 * (g) the advanced electronic signature or advanced electronic seal of the issuing qualified trust service provider;
 * (h) the location where the certificate supporting the advanced electronic signature or advanced electronic seal
 *     referred to in point (g) is available free of charge;
 * (i) the location of the services that can be used to enquire as to the validity status of the qualified certificate;
 * (j) where the electronic seal creation data related to the electronic seal validation data is located in a qualified
 *     electronic seal creation device, an appropriate indication of this, at least in a form suitable for automated
 *     processing.
 * </pre>
 *
 * ====================================================================================================================
 *
 * REAL WORLD EXAMPLES OF EIDAS CERTIFICATES;
 *
 * Konsentus provides a service for providing regulatory information about a TPP. Their API provides a way identifying
 * a TPP from information extracted from an eIDAS certificate.  It does not accept the actual eIDAS certificate!
 * Currently their API takes a base64 encoded JSON structure that contains the information that one would expect to
 * find in an eIDAS certificate. An example JSON structure below;
 * <code>
 * {
 *  "version": 0,
 *  "subject":
 *   { "commonName": "eIDAS Test XA",
 *     "organizationName": "Swedish E-Identification Board",
 *     "countryName": "XA" },
 *  "issuer":
 *   { "commonName": "eIDAS Test XA",
 *     "organizationName": "Swedish E-Identification Board",
 *     "countryName": "XA" },
 *  "serial": "015FFA00D5B7",
 *  "notBefore": "2017-11-26T18:24:39.000Z",
 *  "notAfter": "2022-11-26T20:24:39.000Z",
 *  "subjectHash": "fb9a58d3",
 *  "signatureAlgorithm": "sha512WithRSAEncryption",
 *  "fingerPrint": "10:59:15:88:02:96:69:38:CE:A7:6C:9F:7E:B3:86:13:25:CF:2D:2F",
 *  "publicKey":
 *   { "algorithm": "rsaEncryption",
 *     "e": "65537",
 *     "n": "9730A4434A831D617A076363E0BD9",
 *     "bitSize": 2048 },
 *  "altNames": [],
 *  "extensions": {
 *    "organisationIdentifier": "PSDGB-FCA-791622",
 *    "qcStatement": {
 *      "rolesOfPSP": ["PSP_PI", "PSP_AI"],
 *      "nCAName": "Finansinspektionen",
 *      "nCAId": "SFO"
 *    }
 *  }
 * }
 * </code>
 *
 * ASORSYS eIDAS QWAC GENERATOR
 * A German Consulting company called Adorsys have a QWAC generator that is available here;
 * <a href="http://tppserver.cloud.adorsys.de/swagger-ui.html#!/certificate-ctrl/addUsingPOST"></a>
 *
 * It uses the following ASN.1 object id to store the organisationIdentifier in rather than the Konsentus approach
 * that stores the organisationIdentifier as an extension (the implication here is that it would be stored in an
 * ASN.1 extension in a real eIDAS certificate. Our approach should be to put this info in both.
 *
 * <a href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.00.12_20/en_31941205v020012a.pdf"></a>
 *
 * ====================================================================================================================
 *
 * AUTHORITATIVE DOCUMENT ON WHERE EIDAS EXTENSION INFORMATION SHOULD BE STORED
 *
 * The following ETSI document (Draft) specified how some of the extra information should be provided in the certificate;
 * <a href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.00.12_20/en_31941205v020012a.pdf"></a>
 *
 * And this doc specifies how PSD2 specific attributes should be encoded;
 * <a href="https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.01.02_60/ts_119495v010102p.pdf"></a>
 *
 */
public class EidasInformation {

    private Set<Psd2Role>   roles = new HashSet<>();
    private String          caIssuerCertURL;
    private String          ocspUri;
    private String          organisationId;
    private String          ncaName;
    private String          ncaId;



    /**
     * The URL at which the signing certificate of the issuing eIDAS authority may be obtained
     * @return CA ussier cert url
     */
    public String getCaIssuerCertURL() {
        return caIssuerCertURL;
    }

    public void setCaIssuerCertURL(String caIssuerCertURL) {
        this.caIssuerCertURL = caIssuerCertURL;
    }

    /**
     * The URI at which the Online Certificate Status Protocol (OCSP) may be found
     * @return OCSP url
     */
    public String getOcspUri() {
        return ocspUri;
    }

    public void setOcspUri(String ocspUri) {
        this.ocspUri = ocspUri;
    }

    public String getOrganisationId() {
        return organisationId;
    }

    public EidasInformation setOrganisationId(String organisationId) {
        this.organisationId = organisationId;
        return this;
    }

    public void addRole(Psd2Role psd2Role) {
        roles.add(psd2Role);
    }

    public Set<Psd2Role> getPsd2Roles(){
        return this.roles;
    }

    /**
     * Get the National Competent Authority that regulates the TPP who we are generating this
     * eidas PSD2 certificate for.
     * @return NCA Name
     */
    public String getNcaName() {
        return ncaName;
    }

    /**
     * Set the name of the National Competent Authority that regulates the TPP who we are going to generate an eidas
     * PSD2 certificate for.
     * @param ncaName nca name
     */
    public void setNcaName(String ncaName) {
        this.ncaName = ncaName;
    }

    /**
     * Get the id of the the National Competent Authority that regulates the TPP who we are going to generate an eidas
     * PSD2 certificate for.
     * @return NCA ID
     */
    public String getNcaId() {
        return ncaId;
    }

    /**
     * Set the id of the the National Competent Authority that regulates the TPP who we are going to generate an eidas
     * PSD2 certificate for.
     * @param ncaId nca ID
     */
    public void setNcaId(String ncaId) {
        this.ncaId = ncaId;
    }

}
