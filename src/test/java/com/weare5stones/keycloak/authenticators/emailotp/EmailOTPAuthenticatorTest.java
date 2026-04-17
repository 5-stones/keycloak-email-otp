package com.weare5stones.keycloak.authenticators.emailotp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Answers;

class EmailOTPAuthenticatorTest {

  @Test
  void authenticateSendsEmailOnlyOnceAndChallengesForm() throws Exception {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.authNotes.put("emailSent", "false");

    authenticator.authenticate(tc.context);

    assertEquals("true", tc.authNotes.get("emailSent"));
    assertNotNull(tc.authNotes.get("code"));
    assertNotNull(tc.authNotes.get("ttl"));
    assertNotNull(tc.authNotes.get("remainingRetries"));
    verify(tc.context).challenge(tc.formResponse);
    verify(tc.emailTemplateProvider).send(anyString(), any(), anyString(), any());

    authenticator.authenticate(tc.context);
    verify(tc.emailTemplateProvider).send(anyString(), any(), anyString(), any());
  }

  @Test
  void authenticateHandlesErrorsWithFailureChallenge() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.configMap.remove(EmailOTPAuthenticatorFactory.CONFIG_PROP_TTL);

    authenticator.authenticate(tc.context);

    verify(tc.context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), eq(tc.errorResponse));
  }

  @Test
  void actionResendFailsWhenRetryLimitReached() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("resend", "resend");
    tc.authNotes.put("remainingResendRetries", "0");

    authenticator.action(tc.context);

    verify(tc.context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(tc.formResponse));
    verify(tc.context, never()).challenge(any(Response.class));
  }

  @Test
  void actionResendSendsExistingCodeAndDecrementsRetry() throws Exception {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("resend", "resend");
    tc.authNotes.put("code", "ABC123");
    tc.authNotes.put("remainingResendRetries", "2");

    authenticator.action(tc.context);

    verify(tc.context).challenge(tc.formResponse);
    verify(tc.emailTemplateProvider).send(anyString(), any(), anyString(), any());
    assertEquals("1", tc.authNotes.get("remainingResendRetries"));
    assertEquals("ABC123", tc.authNotes.get("code"));
  }

  @Test
  void actionResendHandlesErrorsWithFailureChallenge() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("resend", "resend");
    tc.configMap.remove(EmailOTPAuthenticatorFactory.CONFIG_PROP_TTL);

    authenticator.action(tc.context);

    verify(tc.context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), eq(tc.errorResponse));
  }

  @Test
  void actionFailsWithInternalErrorWhenOtpStateMissing() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("code", "123456");

    authenticator.action(tc.context);

    verify(tc.context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), eq(tc.errorResponse));
  }

  @Test
  void actionFailsWithInternalErrorWhenTtlMissingButCodeExists() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("code", "123456");
    tc.authNotes.put("code", "123456");

    authenticator.action(tc.context);

    verify(tc.context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), eq(tc.errorResponse));
  }

  @Test
  void actionFailsWithExpiredCodeWhenTtlPassed() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("code", "123456");
    tc.authNotes.put("code", "123456");
    tc.authNotes.put("ttl", Long.toString(System.currentTimeMillis() - 1000));

    authenticator.action(tc.context);

    verify(tc.context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), eq(tc.errorResponse));
  }

  @Test
  void actionMarksUserEmailVerifiedAndSucceeds() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    when(tc.user.isEmailVerified()).thenReturn(false);
    tc.formParams.putSingle("code", "123456");
    tc.authNotes.put("code", "123456");
    tc.authNotes.put("ttl", Long.toString(System.currentTimeMillis() + 60_000));

    authenticator.action(tc.context);

    verify(tc.user).setEmailVerified(true);
    verify(tc.context).success();
  }

  @Test
  void actionSucceedsWithoutChangingVerificationWhenAlreadyVerified() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    when(tc.user.isEmailVerified()).thenReturn(true);
    tc.formParams.putSingle("code", "123456");
    tc.authNotes.put("code", "123456");
    tc.authNotes.put("ttl", Long.toString(System.currentTimeMillis() + 60_000));

    authenticator.action(tc.context);

    verify(tc.user, never()).setEmailVerified(true);
    verify(tc.context).success();
  }

  @Test
  void actionFailsWithRemainingAttemptsMessageForInvalidCode() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("code", "wrong");
    tc.authNotes.put("code", "123456");
    tc.authNotes.put("ttl", Long.toString(System.currentTimeMillis() + 60_000));
    tc.authNotes.put("remainingRetries", "2");

    authenticator.action(tc.context);

    assertEquals("1", tc.authNotes.get("remainingRetries"));
    verify(tc.context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(tc.formResponse));
  }

  @Test
  void actionFailsImmediatelyForInvalidCodeWithoutRemainingAttempts() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("code", "wrong");
    tc.authNotes.put("code", "123456");
    tc.authNotes.put("ttl", Long.toString(System.currentTimeMillis() + 60_000));
    tc.authNotes.put("remainingRetries", "0");

    authenticator.action(tc.context);

    verify(tc.context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
  }

  @Test
  void actionTreatsNonResendValueAsRegularCodeValidationPath() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();

    tc.formParams.putSingle("resend", "again");
    tc.formParams.putSingle("code", "wrong");
    tc.authNotes.put("code", "123456");
    tc.authNotes.put("ttl", Long.toString(System.currentTimeMillis() + 60_000));
    tc.authNotes.put("remainingRetries", "0");

    authenticator.action(tc.context);

    verify(tc.context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
  }

  @Test
  void configuredForAndRequiresUserExposeExpectedFlags() {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    UserModel user = mock(UserModel.class);

    when(user.getEmail()).thenReturn("user@example.org");
    assertTrue(authenticator.requiresUser());
    assertTrue(authenticator.configuredFor(null, null, user));

    when(user.getEmail()).thenReturn(null);
    assertFalse(authenticator.configuredFor(null, null, user));

    authenticator.setRequiredActions(null, null, user);
    authenticator.close();
  }

  @Test
  void getCodeUsesConfiguredCharacterSetsAndFallback() throws Exception {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    Method getCodeMethod = EmailOTPAuthenticator.class.getDeclaredMethod("getCode", AuthenticatorConfigModel.class);
    getCodeMethod.setAccessible(true);

    AuthenticatorConfigModel cfgUpper = newConfig("6", "true", "false", "false");
    String upperCode = (String) getCodeMethod.invoke(authenticator, cfgUpper);
    assertEquals(6, upperCode.length());
    assertTrue(upperCode.chars().allMatch(Character::isUpperCase));

    AuthenticatorConfigModel cfgLower = newConfig("6", "false", "true", "false");
    String lowerCode = (String) getCodeMethod.invoke(authenticator, cfgLower);
    assertEquals(6, lowerCode.length());
    assertTrue(lowerCode.chars().allMatch(Character::isLowerCase));

    AuthenticatorConfigModel cfgNumbers = newConfig("6", "false", "false", "true");
    String numberCode = (String) getCodeMethod.invoke(authenticator, cfgNumbers);
    assertEquals(6, numberCode.length());
    assertTrue(numberCode.chars().allMatch(Character::isDigit));

    AuthenticatorConfigModel cfgFallback = newConfig("8", "false", "false", "false");
    String fallbackCode = (String) getCodeMethod.invoke(authenticator, cfgFallback);
    assertEquals(8, fallbackCode.length());
    assertTrue(fallbackCode.chars().allMatch(c -> Character.isLetterOrDigit((char) c)));
  }

  @Test
  void simulationModeSkipsEmailProviderSend() throws Exception {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();
    tc.configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_SIMULATION, "true");

    authenticator.authenticate(tc.context);

    verify(tc.keycloakSession, never()).getProvider(EmailTemplateProvider.class);
  }

  @Test
  void authenticateUsesRealmNameWhenDisplayNameIsEmpty() throws Exception {
    EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
    TestContext tc = new TestContext();
    when(tc.realm.getDisplayName()).thenReturn("");
    when(tc.realm.getName()).thenReturn("realm-fallback-name");

    authenticator.authenticate(tc.context);

    verify(tc.emailTemplateProvider).send(anyString(), any(), anyString(), any());
  }

  private static AuthenticatorConfigModel newConfig(String length, String upper, String lower, String numbers) {
    AuthenticatorConfigModel cfg = new AuthenticatorConfigModel();
    Map<String, String> values = new HashMap<>();
    values.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_LENGTH, length);
    values.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_UPPERCASE, upper);
    values.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_LOWERCASE, lower);
    values.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_NUMBERS, numbers);
    cfg.setConfig(values);
    return cfg;
  }

  private static final class TestContext {
    final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    final KeycloakSession keycloakSession = mock(KeycloakSession.class);
    final RealmModel realm = mock(RealmModel.class);
    final UserModel user = mock(UserModel.class);
    final EmailTemplateProvider emailTemplateProvider = mock(EmailTemplateProvider.class, Answers.RETURNS_SELF);
    final LoginFormsProvider formsProvider = mock(LoginFormsProvider.class, Answers.RETURNS_SELF);
    final HttpRequest httpRequest = mock(HttpRequest.class);
    final MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
    final Map<String, String> authNotes = new HashMap<>();
    final Map<String, String> configMap = new HashMap<>();
    final Response formResponse = mock(Response.class);
    final Response errorResponse = mock(Response.class);

    TestContext() {
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_TTL, "300");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_EMAIL_SUBJECT, "Temporary Authentication Code");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_LENGTH, "6");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_MAX_RETRIES, "2");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_MAX_RESEND_RETRIES, "3");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_UPPERCASE, "true");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_LOWERCASE, "true");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_NUMBERS, "true");
      configMap.put(EmailOTPAuthenticatorFactory.CONFIG_PROP_SIMULATION, "false");

      AuthenticatorConfigModel authenticatorConfigModel = new AuthenticatorConfigModel();
      authenticatorConfigModel.setConfig(configMap);

      when(context.getAuthenticationSession()).thenReturn(authSession);
      when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfigModel);
      when(context.getSession()).thenReturn(keycloakSession);
      when(context.getRealm()).thenReturn(realm);
      when(context.getUser()).thenReturn(user);
      when(context.form()).thenReturn(formsProvider);
      when(context.getHttpRequest()).thenReturn(httpRequest);
      when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
      when(keycloakSession.getProvider(EmailTemplateProvider.class)).thenReturn(emailTemplateProvider);
      when(realm.getDisplayName()).thenReturn("Demo Realm");
      when(realm.getName()).thenReturn("demo");
      when(user.getEmail()).thenReturn("user@example.org");
      when(formsProvider.createForm(anyString())).thenReturn(formResponse);
      when(formsProvider.createErrorPage(any(Response.Status.class))).thenReturn(errorResponse);

      when(authSession.getAuthNote(anyString())).thenAnswer(invocation -> authNotes.get(invocation.getArgument(0)));
      doAnswer(invocation -> {
        authNotes.put(invocation.getArgument(0), invocation.getArgument(1));
        return null;
      }).when(authSession).setAuthNote(anyString(), anyString());
    }
  }
}
