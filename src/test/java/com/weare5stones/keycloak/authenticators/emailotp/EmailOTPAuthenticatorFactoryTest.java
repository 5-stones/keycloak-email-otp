package com.weare5stones.keycloak.authenticators.emailotp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;

class EmailOTPAuthenticatorFactoryTest {

  @Test
  void exposesExpectedMetadataAndBehavior() {
    EmailOTPAuthenticatorFactory factory = new EmailOTPAuthenticatorFactory();

    assertEquals("emailotp-authenticator", factory.getId());
    assertEquals("Email TOTP Authentication", factory.getDisplayType());
    assertEquals("Validates a TOTP sent via email to the users email address.", factory.getHelpText());
    assertEquals("otp", factory.getReferenceCategory());
    assertTrue(factory.isConfigurable());
    assertFalse(factory.isUserSetupAllowed());
    assertArrayEquals(
      new AuthenticationExecutionModel.Requirement[] {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
      },
      factory.getRequirementChoices()
    );
  }

  @Test
  void returnsAllConfigPropertiesInOrder() {
    EmailOTPAuthenticatorFactory factory = new EmailOTPAuthenticatorFactory();

    List<ProviderConfigProperty> props = factory.getConfigProperties();

    assertEquals(9, props.size());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_SIMULATION, props.get(0).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_EMAIL_SUBJECT, props.get(1).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_LENGTH, props.get(2).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_TTL, props.get(3).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_MAX_RETRIES, props.get(4).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_MAX_RESEND_RETRIES, props.get(5).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_UPPERCASE, props.get(6).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_LOWERCASE, props.get(7).getName());
    assertEquals(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_NUMBERS, props.get(8).getName());
  }

  @Test
  void lifecycleMethodsAreNoOpsAndCreateAuthenticator() {
    EmailOTPAuthenticatorFactory factory = new EmailOTPAuthenticatorFactory();

    factory.init(null);
    factory.postInit(null);
    factory.close();

    assertInstanceOf(EmailOTPAuthenticator.class, factory.create(null));
  }
}
