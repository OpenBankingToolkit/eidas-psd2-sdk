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

import com.forgerock.cert.eidas.EidasInformation;

public class CertificateConfiguration {

    public String cn;
    public String ou;
    public String o;
    public String l;
    public String st;
    public String c;
    public String oi;
    public EidasInformation eidasInfo;

    public String getCn() {
        return cn;
    }

    public CertificateConfiguration setCn(String cn) {
        this.cn = cn;
        return this;
    }

    public String getOu() {
        return ou;
    }

    public CertificateConfiguration setOu(String ou) {
        this.ou = ou;
        return this;
    }

    public String getO() {
        return o;
    }

    public CertificateConfiguration setO(String o) {
        this.o = o;
        return this;
    }

    public String getL() {
        return l;
    }

    public CertificateConfiguration setL(String l) {
        this.l = l;
        return this;
    }

    public String getSt() {
        return st;
    }

    public CertificateConfiguration setSt(String st) {
        this.st = st;
        return this;
    }

    public String getC() {
        return c;
    }

    public CertificateConfiguration setC(String c) {
        this.c = c;
        return this;
    }

    public String getOi() { return oi; }

    public CertificateConfiguration setOi(String oi) {
        this.oi = oi;
        return this;
    }

    public EidasInformation getEidasInfo() {
        return eidasInfo;
    }

    public CertificateConfiguration setEidasInfo(EidasInformation eidasInfo) {
        this.eidasInfo = eidasInfo;
        return this;
    }
}
