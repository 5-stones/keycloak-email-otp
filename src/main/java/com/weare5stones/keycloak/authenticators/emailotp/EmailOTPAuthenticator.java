package com.weare5stones.keycloak.authenticators.emailotp;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

public class EmailOTPAuthenticator implements Authenticator {

  private static final String TOTP_FORM = "totp-form.ftl";
  private static final String TOTP_EMAIL = "totp-email.ftl";
  private static final Logger logger = Logger.getLogger(EmailOTPAuthenticator.class);

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    KeycloakSession session = context.getSession();
    UserModel user = context.getUser();

    int length = Integer.parseInt(config.getConfig().get("length"));
    int ttl = Integer.parseInt(config.getConfig().get("ttl"));
    String emailSubject = config.getConfig().get("emailSubject");
    Boolean isSimulation = Boolean.parseBoolean(config.getConfig().getOrDefault("simulation", "false"));

    String code = SecretGenerator
        .getInstance()
        .randomString(length);
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    authSession.setAuthNote("code", code);
    authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

    try {
      RealmModel realm = context.getRealm();

      if (isSimulation) {
        logger.warn(String.format(
            "***** SIMULATION MODE ***** Would send a TOTP email to %s with code: %s",
            user.getEmail(),
            code));
      } else {
        String realmName = Strings.isNullOrEmpty(realm.getDisplayName()) ? realm.getName() : realm.getDisplayName();
        List<Object> subjAttr = ImmutableList.of(realmName);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);
        attributes.put("ttl", Math.floorDiv(ttl, 60));
        session.getProvider(EmailTemplateProvider.class)
            .setAuthenticationSession(authSession)
            .setRealm(realm)
            .setUser(user)
            .setAttribute("realmName", realmName)
            .send(
                emailSubject,
                subjAttr,
                TOTP_EMAIL,
                attributes);
      }

      context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TOTP_FORM));
    } catch (Exception e) {
      logger.error("An error occurred when attempting to email an TOTP auth:", e);
      context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
          context.form().setError("emailTOTPEmailNotSent", e.getMessage())
              .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String code = authSession.getAuthNote("code");
    String ttl = authSession.getAuthNote("ttl");

    if (code == null || ttl == null) {
      context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
          context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
      return;
    }

    boolean isValid = enteredCode.equals(code);
    if (isValid) {
      if (Long.parseLong(ttl) < System.currentTimeMillis()) {
        // expired
        context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
            context.form().setError("emailTOTPCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
      } else {
        // valid
        context.success();
      }
    } else {
      // invalid
      AuthenticationExecutionModel execution = context.getExecution();
      if (execution.isRequired()) {
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
            context.form().setAttribute("realm", context.getRealm())
                .setError("emailTOTPCodeInvalid").createForm(TOTP_FORM));
      } else if (execution.isConditional() || execution.isAlternative()) {
        context.attempted();
      }
    }
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return user.getEmail() != null;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public void close() {
  }

}
