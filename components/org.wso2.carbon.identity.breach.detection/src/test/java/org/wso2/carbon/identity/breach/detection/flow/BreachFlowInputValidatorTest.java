/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.breach.detection.flow;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.breach.detection.constants.BreachDetectionConstants.ErrorMessages;
import org.wso2.carbon.identity.breach.detection.engine.BreachEvaluationEngine;
import org.wso2.carbon.identity.breach.detection.internal.BreachDetectionDataHolder;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.validation.FlowInputValidationRequest;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * The flow input validator against a stub source, so the flow outcome can be checked for every decision.
 */
public class BreachFlowInputValidatorTest {

    private static final String TENANT = "example.com";
    private static final String PASSWORD = "Password@1";

    private final List<String> checkedTenants = new ArrayList<>();
    private final List<Credential> checkedCredentials = new ArrayList<>();
    private volatile Decision answer = Decision.ACCEPT;
    private BreachSource source;
    private BreachEvaluationEngine previousEngine;

    @BeforeMethod
    public void setUp() {

        checkedTenants.clear();
        checkedCredentials.clear();
        answer = Decision.ACCEPT;
        source = new RecordingSource();
        previousEngine = BreachDetectionDataHolder.getInstance().getEvaluationEngine();
        BreachDetectionDataHolder.getInstance().setEvaluationEngine(new BreachEvaluationEngine());
        BreachDetectionDataHolder.getInstance().bindSource(source);
    }

    @AfterMethod
    public void tearDown() {

        BreachDetectionDataHolder.getInstance().unbindSource(source);
        BreachDetectionDataHolder.getInstance().setEvaluationEngine(previousEngine);
    }

    @Test
    public void handlesOnlyAStepThatSubmitsAPassword() {

        BreachFlowInputValidator validator = new BreachFlowInputValidator(true);

        assertTrue(validator.canHandle(request(BreachFlowInputValidator.PASSWORD_INPUT, PASSWORD)));
        assertFalse(validator.canHandle(request(BreachFlowInputValidator.PASSWORD_INPUT, "")));
        assertFalse(validator.canHandle(request("http://wso2.org/claims/emailaddress", "user@example.com")));
    }

    @Test
    public void acceptedPasswordLetsTheStepContinue() throws FlowEngineException {

        new BreachFlowInputValidator(true).validate(request(BreachFlowInputValidator.PASSWORD_INPUT, PASSWORD));

        assertEquals(checkedTenants.size(), 1);
        assertEquals(checkedTenants.get(0), TENANT);
    }

    @Test
    public void breachedPasswordIsRefusedWithTheBreachError() {

        answer = Decision.REFUSE_BREACHED;

        FlowEngineClientException e = assertRefused();

        assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_BREACHED_PASSWORD.getCode());
        assertEquals(e.getMessage(), ErrorMessages.ERROR_CODE_BREACHED_PASSWORD.getMessage());
    }

    @Test
    public void unverifiedPasswordIsRefusedWithTheCannotVerifyError() {

        answer = Decision.REFUSE_UNVERIFIED;

        FlowEngineClientException e = assertRefused();

        assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_CANNOT_VERIFY.getCode());
        assertEquals(e.getMessage(), ErrorMessages.ERROR_CODE_CANNOT_VERIFY.getMessage());
    }

    @Test
    public void errorDoesNotContainThePassword() {

        answer = Decision.REFUSE_BREACHED;

        FlowEngineClientException e = assertRefused();

        assertFalse(e.getMessage().contains(PASSWORD));
        assertFalse(String.valueOf(e.getDescription()).contains(PASSWORD));
    }

    @Test
    public void credentialIsClearedAfterTheCheck() throws FlowEngineException {

        new BreachFlowInputValidator(true).validate(request(BreachFlowInputValidator.PASSWORD_INPUT, PASSWORD));

        assertEquals(checkedCredentials.size(), 1);
        assertTrue(checkedCredentials.get(0).isCleared());
    }

    @Test
    public void deploymentSwitchOffSkipsTheCheck() throws FlowEngineException {

        answer = Decision.REFUSE_BREACHED;

        new BreachFlowInputValidator(false).validate(request(BreachFlowInputValidator.PASSWORD_INPUT, PASSWORD));

        assertTrue(checkedTenants.isEmpty());
    }

    @Test
    public void engineNotStartedSkipsTheCheck() throws FlowEngineException {

        answer = Decision.REFUSE_BREACHED;
        BreachDetectionDataHolder.getInstance().setEvaluationEngine(null);

        new BreachFlowInputValidator(true).validate(request(BreachFlowInputValidator.PASSWORD_INPUT, PASSWORD));

        assertTrue(checkedTenants.isEmpty());
    }

    private FlowEngineClientException assertRefused() {

        BreachFlowInputValidator validator = new BreachFlowInputValidator(true);
        FlowInputValidationRequest request = request(BreachFlowInputValidator.PASSWORD_INPUT, PASSWORD);
        try {
            validator.validate(request);
        } catch (FlowEngineClientException e) {
            assertNotNull(e.getErrorCode());
            return e;
        } catch (FlowEngineException e) {
            fail("A refused password must be a client error, not " + e.getClass().getSimpleName() + ".");
        }
        fail("The password was not refused.");
        return null;
    }

    private static FlowInputValidationRequest request(String inputKey, String inputValue) {

        FlowExecutionContext context = new FlowExecutionContext();
        context.setTenantDomain(TENANT);
        context.setFlowType("REGISTRATION");
        context.getUserInputData().put(inputKey, inputValue);
        return new FlowInputValidationRequest(context);
    }

    /**
     * Answers with the decision the test set, and records what it was asked.
     */
    private class RecordingSource implements BreachSource {

        @Override
        public String getId() {

            return "flowTestSource";
        }

        @Override
        public int getPriority() {

            return 1;
        }

        @Override
        public void configure(SourceConfiguration configuration) {

        }

        @Override
        public boolean isEnabled(String tenantDomain) {

            return true;
        }

        @Override
        public Decision check(Credential credential, String tenantDomain) {

            checkedTenants.add(tenantDomain);
            checkedCredentials.add(credential);
            return answer;
        }
    }
}
