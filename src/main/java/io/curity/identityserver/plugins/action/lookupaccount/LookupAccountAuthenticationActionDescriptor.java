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

import se.curity.identityserver.sdk.authenticationaction.AuthenticationAction;
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticationActionPluginDescriptor;

public final class LookupAccountAuthenticationActionDescriptor implements AuthenticationActionPluginDescriptor<LookupAccountAuthenticationActionConfig>
{
    @Override
    public Class<? extends AuthenticationAction> getAuthenticationAction()
    {
        return LookupAccountAuthenticationAction.class;
    }

    @Override
    public Class<? extends AuthenticationAction> getBackchannelAuthenticationAction()
    {
        return LookupAccountAuthenticationAction.class;
    }

    @Override
    public String getPluginImplementationType()
    {
        return "lookup-account";
    }

    @Override
    public Class<? extends LookupAccountAuthenticationActionConfig> getConfigurationType()
    {
        return LookupAccountAuthenticationActionConfig.class;
    }
}
