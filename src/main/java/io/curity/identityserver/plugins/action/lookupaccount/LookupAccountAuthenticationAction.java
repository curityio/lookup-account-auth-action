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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.*;
import se.curity.identityserver.sdk.authenticationaction.AuthenticationAction;
import se.curity.identityserver.sdk.authenticationaction.AuthenticationActionContext;
import se.curity.identityserver.sdk.authenticationaction.AuthenticationActionResult;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.service.AccountManager;

public final class LookupAccountAuthenticationAction implements AuthenticationAction {
    private static final Logger _logger = LoggerFactory.getLogger(LookupAccountAuthenticationAction.class);

    private static final String ATTRIBUTES_KEY = "account";  // Compliant
    private final AccountManager _accountManager;
    private final boolean _abortAuthenticationIfUserNotFound;
    private final LookupAccountAuthenticationActionConfig.LookupMethod _lookupMethod;
    private final LookupAccountAuthenticationActionConfig.AttributeLocation _attributeLocation;
    private final String _customAttributeName;

    public LookupAccountAuthenticationAction(LookupAccountAuthenticationActionConfig configuration) {
        _accountManager = configuration.getAccountManager();
        _abortAuthenticationIfUserNotFound = configuration.getAbortAuthenticationIfUserNotFound();
        _lookupMethod = configuration.getLookupMethod();
        _customAttributeName = configuration.getCustomAttributeNameLookup().trim();
        _attributeLocation = configuration.getAttributeLocation();
    }

    @Override
    public AuthenticationActionResult apply(AuthenticationActionContext context) {
        AuthenticationAttributes authenticationAttributes = context.getAuthenticationAttributes();
        AuthenticationActionAttributes authenticationActionAttributes = context.getActionAttributes();

        @Nullable String customAttributeValue = authenticationAttributes.getSubjectAttributes().get(_customAttributeName) == null ? null
                : authenticationAttributes.getSubjectAttributes().get(_customAttributeName).getAttributeValue().getValue().toString().trim();

        @Nullable AccountAttributes accountAttributes = customAttributeValue == null ? null : getAccountAttributes(customAttributeValue);

        if (accountAttributes == null && _abortAuthenticationIfUserNotFound) {
            _logger.debug("Account not found");
            // Error message has been kept generic to prevent account enumeration.
            return AuthenticationActionResult.failedResult("Provided credentials were invalid", ErrorCode.ACCESS_DENIED);
        } else if (accountAttributes == null) {
            // Continue with the authentication flow even if the account is not found.
            return AuthenticationActionResult.successfulResult(authenticationAttributes);
        }

        Attributes nonEmptyAttributes = accountAttributes.stream().filter(accountAttribute -> !accountAttribute.getAttributeValue().isEmpty()).collect(AttributeCollector.toAttributes());

        switch (_attributeLocation) {
            case SUBJECT_ATTRIBUTES ->
                    authenticationAttributes = authenticationAttributes.withSubjectAttribute(Attribute.of(ATTRIBUTES_KEY, MapAttributeValue.of(nonEmptyAttributes)));

            case CONTEXT_ATTRIBUTES ->
                    authenticationAttributes = authenticationAttributes.withContextAttribute(Attribute.of(ATTRIBUTES_KEY, MapAttributeValue.of(nonEmptyAttributes)));

            case ACTION_ATTRIBUTES ->
                    authenticationActionAttributes = authenticationActionAttributes.with(Attribute.of(ATTRIBUTES_KEY, MapAttributeValue.of(nonEmptyAttributes)));

        }
        return AuthenticationActionResult.successfulResult(authenticationAttributes, authenticationActionAttributes);

    }

    private AccountAttributes getAccountAttributes(String customAttributeValue) {
        return switch (_lookupMethod) {
            case BY_USERNAME -> _accountManager.getByUserName(customAttributeValue);
            case BY_EMAIL -> _accountManager.getByEmail(customAttributeValue);
            case BY_PHONE -> _accountManager.getByPhone(customAttributeValue);
        };
    }
}