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
package com.forgerock.test_helpers;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

public class RegexMatcher extends BaseMatcher {
    private final String regex;

    public RegexMatcher(String regex){
        this.regex = regex;
    }

    public boolean matches(Object o){
        return ((String)o).matches(regex);

    }

    @Override
    public void describeTo(Description description){
        description.appendText("matches regex=");
    }

    public static RegexMatcher matches(String regex){
        return new RegexMatcher(regex);
    }
}
