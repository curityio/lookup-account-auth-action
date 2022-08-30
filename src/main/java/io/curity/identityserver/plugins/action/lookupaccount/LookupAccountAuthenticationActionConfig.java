/*
 *  Copyright 2022 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugins.action.lookupaccount;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.DefaultString;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.config.annotation.Suggestions;
import se.curity.identityserver.sdk.service.AccountManager;

public interface LookupAccountAuthenticationActionConfig extends Configuration
{
    AccountManager getAccountManager();

    @Description("When true authentication flow will be aborted if the user is not found")
    @DefaultBoolean(false) Boolean getAbortAuthenticationIfUserNotFound();

    @Description("The attributes location")
    @DefaultEnum("SUBJECT_ATTRIBUTES")
    AttributeLocation getAttributeLocation();

    @Description("Select the method to lookup account attributes")
    @DefaultEnum("BY_USERNAME")
    LookupMethod getLookupMethod();

    @Description("Specify the attribute to be used by the lookup method for searching the user")
    @DefaultString("subject")
    @Suggestions({"email"})
    String getCustomAttributeNameLookup();

    enum LookupMethod
    {
        BY_USERNAME, BY_EMAIL, BY_PHONE
    }

    enum AttributeLocation
    {
        SUBJECT_ATTRIBUTES,
        CONTEXT_ATTRIBUTES,
        ACTION_ATTRIBUTES
    }
    }

