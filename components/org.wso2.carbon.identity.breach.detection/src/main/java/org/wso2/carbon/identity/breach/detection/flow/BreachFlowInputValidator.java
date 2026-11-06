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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.detection.constants.BreachDetectionConstants;
import org.wso2.carbon.identity.breach.detection.engine.BreachEvaluationEngine;
import org.wso2.carbon.identity.breach.detection.internal.BreachDetectionDataHolder;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.validation.FlowInputValidationRequest;
import org.wso2.carbon.identity.flow.execution.engine.validation.FlowInputValidator;

/**
 * Flow input validator that refuses breached passwords when a flow step submits them.
 * <p>
 * The listener checks a password only when it is written, which in a registration flow happens after the last
 * step. This validator runs the same evaluation when the password step is submitted, so the flow shows the error
 * on that step. The listener still runs when the password is written.
 */
public class BreachFlowInputValidator implements FlowInputValidator {

    private static final Log LOG = LogFactory.getLog(BreachFlowInputValidator.class);

    static final String NAME = "breachedPasswordValidator";

    /** Identifier of the password input in a flow step. */
    static final String PASSWORD_INPUT = "password";

    private final boolean enabledAtDeployment;

    /**
     * @param enabledAtDeployment The deployment switch of the listener. The validator follows the same switch.
     */
    public BreachFlowInputValidator(boolean enabledAtDeployment) {

        this.enabledAtDeployment = enabledAtDeployment;
    }

    @Override
    public String getName() {

        return NAME;
    }

    /**
     * Run only for a step that submits a password. This reads no configuration.
     */
    @Override
    public boolean canHandle(FlowInputValidationRequest request) {

        String password = request.getInputs().get(PASSWORD_INPUT);
        return password != null && !password.isEmpty();
    }

    @Override
    public void validate(FlowInputValidationRequest request) throws FlowEngineException {

        if (!enabledAtDeployment) {
            return;
        }

        BreachEvaluationEngine engine = BreachDetectionDataHolder.getInstance().getEvaluationEngine();
        if (engine == null) {
            LOG.debug("Breach detection is not fully started yet. The flow input is not evaluated.");
            return;
        }

        // The engine clears the credential once it has been evaluated.
        Credential candidate = new Credential(request.getInputs().get(PASSWORD_INPUT).toCharArray());
        Decision decision = engine.evaluate(candidate, request.getTenantDomain());

        switch (decision) {
            case REFUSE_BREACHED:
                throw rejection(BreachDetectionConstants.ErrorMessages.ERROR_CODE_BREACHED_PASSWORD);
            case REFUSE_UNVERIFIED:
                throw rejection(BreachDetectionConstants.ErrorMessages.ERROR_CODE_CANNOT_VERIFY);
            default:
                return;
        }
    }

    private FlowEngineClientException rejection(BreachDetectionConstants.ErrorMessages error) {

        // The flow engine shows the message on the step, so it uses the same text as the listener.
        return new FlowEngineClientException(error.getCode(), error.getMessage(), error.getMessage());
    }
}
