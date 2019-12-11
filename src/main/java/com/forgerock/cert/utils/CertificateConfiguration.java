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
