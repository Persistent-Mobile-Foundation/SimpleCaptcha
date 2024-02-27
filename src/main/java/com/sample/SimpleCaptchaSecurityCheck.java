package com.sample;

import com.ibm.mfp.security.checks.base.CredentialsValidationSecurityCheck;
import com.ibm.mfp.server.security.external.checks.SecurityCheckConfiguration;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

/**
 * This security checks implements an example of a captcha by calculating the sum
 * of two operands that are sent as a challenge.
 * The challenge created is a JSON in the format of {"captcha" : "x + y"}
 * The challenge answer should bea  JSON in the format of {"answer" : "z"}
 * If z = x + y then the credentials are valid and the security check goes in to "success" state
 * (this is implemented in the base class CredentialsValidationSecurityCheck)
 *
 */
public class SimpleCaptchaSecurityCheck extends CredentialsValidationSecurityCheck {

    private transient String errorMsg;
    private Random rand;

    // The captcha challenge expected result
    private int expectedResult;

    @Override
    public SecurityCheckConfiguration createConfiguration(Properties properties) {
        return new SimpleCaptchaConfig(properties);
    }
    @Override
    protected SimpleCaptchaConfig getConfiguration() {
        return (SimpleCaptchaConfig) super.getConfiguration();
    }

    /**
     * Validate the credentials, sums the operands that were sent in the challenge against the answer that was
     * sent in the credentials
     * @param credentials
     * @return true if the answer equals the expected result, false otherwise
     */
    protected boolean validateCredentials(Map<String, Object> credentials) {
        boolean valid;
        String fieldResponse = (String) credentials.get("answer");
        try {
            int answer = Integer.parseInt(fieldResponse);
            valid = (answer == expectedResult);
        } catch(NumberFormatException e) {
            valid = false;
        }
        if (!valid) errorMsg = "Incorrect answer";
        return valid;
    }

    /**
     * Creates a challenge to be sent to the request
     * @return the challenge object
     */
    @Override
    protected Map<String, Object> createChallenge() {
        if(rand == null) rand = new Random();

        // The max number to generate a random number from, as configured in the SimpleCaptchaConfig file
        int max = getConfiguration().maxOperator;

        int operandA = rand.nextInt(max); // Random number 0-max
        int operandB = rand.nextInt(max); // Random number 0-max
        expectedResult = operandA + operandB;

        Map<String, Object> challenge = new HashMap();
        challenge.put("captcha", buildCaptchaMessage(operandA, operandB));
        challenge.put("message", errorMsg);
        return challenge;
    }

    private String buildCaptchaMessage(int operandA, int operandB) {
        return Integer.toString(operandA) + " + " + Integer.toString(operandB);
    }
}
