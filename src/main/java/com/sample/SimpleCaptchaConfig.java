package com.sample;

import com.ibm.mfp.security.checks.base.CredentialsValidationSecurityCheckConfig;

import java.util.Properties;

/**
 * Configuration class for SimpleCaptchaSecurityCheck
 * This class inherits all the configuration properties from CredentialsValidationSecurityCheckConfig
 * and has an additional field of maxOperator which describes the maximum operator number to be used
 * in the captcha challenge
 */
public class SimpleCaptchaConfig extends CredentialsValidationSecurityCheckConfig {

    public int maxOperator;
    private static final int DEFAULT_MAX_OPERATOR = 11;

    public SimpleCaptchaConfig(Properties properties) {
        super(properties);

        maxOperator = getIntProperty("maxOperator", properties, DEFAULT_MAX_OPERATOR);

        if(maxOperator < 1) {
            addMessage(errors,"maxOperator","the operator max must be at least 1");
        }
    }
}
