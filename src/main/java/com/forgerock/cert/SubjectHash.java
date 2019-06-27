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

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Optional;

public class SubjectHash {
    /**
     * Produce a hash of the subject of the primary certificate
     * @param certChain chain of certificates ordered with the primary certificate first
     * @return hash of the subject of the primary certificate
     * @throws CertificateEncodingException if there is a problem extracting the certificate information.
     */
    public static Optional<String> hash(X509Certificate[] certChain) throws CertificateEncodingException {
        X509Certificate firstCert = certChain != null && certChain.length > 0 ? certChain[0] : null;
        if (firstCert != null) {
            int certHashCode = new JcaX509CertificateHolder(firstCert).getSubject().hashCode();
            return Optional.of(String.valueOf(certHashCode));
        }
        else return Optional.empty();
    }
}
