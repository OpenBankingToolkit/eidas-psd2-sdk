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
package com.forgerock.cert.psd2;

import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;

import net.minidev.json.JSONStyle;
import net.minidev.json.reader.BeansWriterASM;



public class RoleOfPspTest {

    @Test
    public void serializeAndDeserialize(){
        RoleOfPsp role = new RoleOfPsp(Psd2Role.PSP_AI);
        ASN1Primitive serialized = role.toASN1Primitive();

        RoleOfPsp deserialized = RoleOfPsp.getInstance(serialized);
        assertThat(deserialized, is(serialized));
    }

    @Test
    /**
     * Test for issue reported here;
     * https://github.com/OpenBankingToolkit/openbanking-reference-implementation/issues/81
     */
    public void testForIssue81() throws NoSuchFieldException, IOException {
        RoleOfPsp roleOfPsp = new RoleOfPsp(Psd2Role.PSP_AI);
        Field f = RoleOfPsp.class.getDeclaredField("role");
        BeansWriterASM bASM = new BeansWriterASM();
        StringWriter stringWriter = new StringWriter();
        bASM.writeJSONString(roleOfPsp, stringWriter, JSONStyle.NO_COMPRESS);
        String out = stringWriter.toString();
        assertThat(out, is("{\"role\":\"PSP_AI\"}"));
    }
}