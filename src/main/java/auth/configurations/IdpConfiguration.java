package auth.configurations;

import auth.constants.AuthenticationMethod;
import auth.constants.SamlResponseAttributes;
import auth.saml.FederatedUserAuthenticationToken;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.stereotype.Component;

import java.util.*;

@Getter
@Setter
@Component
public class IdpConfiguration extends SharedConfiguration {

  private String defaultEntityId;
  private Map<String, List<String>> attributes = new TreeMap<>();
  private List<FederatedUserAuthenticationToken> users = new ArrayList<>();
  private String acsEndpoint;
  private AuthenticationMethod authenticationMethod;
  private AuthenticationMethod defaultAuthenticationMethod;
  private final String idpPrivateKey;
  private final String idpCertificate;

  @Autowired
  public IdpConfiguration(JKSKeyManager keyManager,
                          @Value("${idp.entity_id}") String defaultEntityId,
                          @Value("${idp.private_key}") String idpPrivateKey,
                          @Value("${idp.certificate}") String idpCertificate,
                          @Value("${idp.auth_method}") String authMethod) {
    super(keyManager);
    this.defaultEntityId = defaultEntityId;
    this.idpPrivateKey = idpPrivateKey;
    this.idpCertificate = idpCertificate;
    this.defaultAuthenticationMethod = AuthenticationMethod.valueOf(authMethod);
    reset();
  }

  /**
   * Reset IDP Configurations
   *
   */
  @Override
  public void reset() {
    setEntityId(defaultEntityId);
    resetAttributes();
    resetKeyStore(defaultEntityId, idpPrivateKey, idpCertificate);
    setAcsEndpoint(null);
    setAuthenticationMethod(this.defaultAuthenticationMethod);
    setSignatureAlgorithm(getDefaultSignatureAlgorithm());
  }

  /**
   * Reset Attributes
   *
   */
  private void resetAttributes() {
    attributes.clear();
    putAttribute(SamlResponseAttributes.UID, "test.user");
    putAttribute(SamlResponseAttributes.CN, "Test User");
    putAttribute(SamlResponseAttributes.NAME, "Test");
    putAttribute(SamlResponseAttributes.SURNAME, "User");
    putAttribute(SamlResponseAttributes.DISPLAY_NAME, "Test User");
    putAttribute(SamlResponseAttributes.MAIL, "testUser@example.com");
    putAttribute(SamlResponseAttributes.ORG_NAME, "testUserOrg.com");
    putAttribute(SamlResponseAttributes.EDU_PERSON_NAME, "testUser@example.com");
  }

  /**
   * Put Attributes in attributes map
   *
   * @param key
   * @param values
   */
  private void putAttribute(String key, String... values) {
    this.attributes.put(key, Arrays.asList(values));
  }

}
