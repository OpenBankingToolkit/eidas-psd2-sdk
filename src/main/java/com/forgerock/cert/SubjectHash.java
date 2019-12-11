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
