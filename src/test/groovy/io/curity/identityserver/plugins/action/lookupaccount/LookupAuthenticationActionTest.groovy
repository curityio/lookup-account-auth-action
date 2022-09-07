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

package io.curity.identityserver.plugins.action.lookupaccount

import io.curity.identityserver.plugins.action.lookupaccount.LookupAccountAuthenticationActionConfig.AttributeLocation
import io.curity.identityserver.plugins.action.lookupaccount.LookupAccountAuthenticationActionConfig.LookupMethod
import se.curity.identityserver.sdk.attribute.*
import se.curity.identityserver.sdk.authenticationaction.AuthenticationActionContext
import se.curity.identityserver.sdk.authenticationaction.AuthenticationActionResult
import se.curity.identityserver.sdk.service.AccountManager
import spock.lang.Specification

class LookupAuthenticationActionTest extends Specification {

    private static final String ID = "some-id"
    private static final String USERNAME = "john"
    private static final String SOURCE_ATTRIBUTE_NAME = "subject"
    private static final String EMAIL_AS_USERNAME = "john@gmail.com"
    private static final String PHONE_AS_USERNAME = "404876543"


    def 'Can find the user when Looked up using username and account attributes are added to the #attributeLocation'(AttributeLocation attributeLocation) {
        given: 'An Authentication action context and configuration'
        def context = Mock(AuthenticationActionContext)
        def action = prepareMockData(context, SOURCE_ATTRIBUTE_NAME, LookupMethod.BY_USERNAME, attributeLocation, Boolean.TRUE)

        when: 'running the action'
        def result = action.apply(context)

        then: 'the result is a successfull authentication action result'
        result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
        verifyResult(attributeLocation, USERNAME, result)

        where:
        attributeLocation << [AttributeLocation.SUBJECT_ATTRIBUTES, AttributeLocation.CONTEXT_ATTRIBUTES, AttributeLocation.ACTION_ATTRIBUTES]

    }


    def 'Can find the user when Looked up using email as the username and account attributes are added to the #attributeLocation'(AttributeLocation attributeLocation) {
        given: 'An Authentication action context and configuration'
        def context = Mock(AuthenticationActionContext)
        def action = prepareMockData(context, SOURCE_ATTRIBUTE_NAME, LookupMethod.BY_EMAIL, attributeLocation, Boolean.FALSE)

        when: 'running the action'
        def result = action.apply(context)

        then: 'the result is a successfull authentication action result'
        result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
        verifyResult(attributeLocation, EMAIL_AS_USERNAME, result)

        where:
        attributeLocation << [AttributeLocation.SUBJECT_ATTRIBUTES, AttributeLocation.CONTEXT_ATTRIBUTES, AttributeLocation.ACTION_ATTRIBUTES]

    }


    def 'Can find the user when Looked up using phone as the username and account attributes are added to the #attributeLocation'(AttributeLocation attributeLocation) {
        given: 'An Authentication action context and configuration'
        def context = Mock(AuthenticationActionContext)
        def action = prepareMockData(context, SOURCE_ATTRIBUTE_NAME, LookupMethod.BY_PHONE, attributeLocation, Boolean.FALSE)

        when: 'running the action'
        def result = action.apply(context)

        then: 'the result is a successfull authentication action result'
        result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
        verifyResult(attributeLocation, PHONE_AS_USERNAME, result)

        where:
        attributeLocation << [AttributeLocation.SUBJECT_ATTRIBUTES, AttributeLocation.CONTEXT_ATTRIBUTES, AttributeLocation.ACTION_ATTRIBUTES]
    }


    def 'Action fails if the source-attribute is not existing and abort-authentication-if-user-not-found is true '() {
        given: 'An Authentication action context and configuration'
        def context = Mock(AuthenticationActionContext)
        def action = prepareMockData(context, "NOT_EXISTING_ATTRIBUTE", LookupMethod.BY_EMAIL,
                AttributeLocation.SUBJECT_ATTRIBUTES, Boolean.TRUE)

        when: 'running the action'
        def result = action.apply(context)

        then: 'the result is a failed authentication action result'
        result instanceof AuthenticationActionResult.FailedAuthenticationActionResult

    }


    def 'Action succeeds if the source-attribute is not existing and abort-authentication-if-user-not-found is False '() {
        given: 'An Authentication action context and configuration'
        def context = Mock(AuthenticationActionContext)
        def action = prepareMockData(context, "NOT_EXISTING_ATTRIBUTE", LookupMethod.BY_EMAIL,
                AttributeLocation.SUBJECT_ATTRIBUTES, Boolean.FALSE)

        when: 'running the action'
        def result = action.apply(context)

        then: 'the result is a successfull authentication action result'
        result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult

    }


    private LookupAccountAuthenticationAction prepareMockData(AuthenticationActionContext context, String sourceAttributeName,
                                                              LookupMethod lookupMethod, AttributeLocation attributeLocation,
                                                              Boolean AbortAuthenticationIfUserNotFound) {
        def accountManager = Mock(AccountManager)
        def config = Mock(LookupAccountAuthenticationActionConfig)

        config.getAccountManager() >> accountManager
        config.getAbortAuthenticationIfUserNotFound() >> AbortAuthenticationIfUserNotFound
        config.getSourceAttributeName() >> sourceAttributeName
        config.getAttributeLocation() >> attributeLocation

        switch (lookupMethod) {
            case LookupMethod.BY_USERNAME:
                context.getAuthenticationAttributes() >> AuthenticationAttributes.of(USERNAME, ContextAttributes.empty())
                context.getActionAttributes() >> AuthenticationActionAttributes.fromAttributes(Attributes.of("userName", USERNAME))
                config.getLookupMethod() >> LookupMethod.BY_USERNAME
                accountManager.getByUserName(USERNAME) >> AccountAttributes.of(ID, USERNAME)
                break
            case LookupMethod.BY_EMAIL:
                context.getAuthenticationAttributes() >> AuthenticationAttributes.of(EMAIL_AS_USERNAME, ContextAttributes.empty())
                context.getActionAttributes() >> AuthenticationActionAttributes.fromAttributes(Attributes.of("userName", EMAIL_AS_USERNAME))
                config.getLookupMethod() >> LookupMethod.BY_EMAIL
                accountManager.getByEmail(EMAIL_AS_USERNAME) >> AccountAttributes.of(ID, EMAIL_AS_USERNAME)
                break
            case LookupMethod.BY_PHONE:
                context.getAuthenticationAttributes() >> AuthenticationAttributes.of(PHONE_AS_USERNAME, ContextAttributes.empty())
                context.getActionAttributes() >> AuthenticationActionAttributes.fromAttributes(Attributes.of("userName", PHONE_AS_USERNAME))
                config.getLookupMethod() >> LookupMethod.BY_PHONE
                accountManager.getByPhone(PHONE_AS_USERNAME) >> AccountAttributes.of(ID, PHONE_AS_USERNAME)
                break
        }

        return new LookupAccountAuthenticationAction(config)
    }


    private void verifyResult(AttributeLocation attributeLocation, String userName, AuthenticationActionResult result) {
        switch (attributeLocation) {
            case AttributeLocation.SUBJECT_ATTRIBUTES:
                result.getAuthenticationAttributes().subject == userName
                break

            case AttributeLocation.CONTEXT_ATTRIBUTES:
                result.getAuthenticationAttributes().getContextAttributes().account.getValue().get("userName") == userName
                break

            case AttributeLocation.ACTION_ATTRIBUTES:
                result.getActionAttributes().account.getValue().get("userName") == userName
                break

        }


    }
}