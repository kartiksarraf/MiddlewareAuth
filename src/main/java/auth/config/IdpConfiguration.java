package auth.config;

import lombok.Getter;
import lombok.Setter;
import auth.saml.FederatedUserAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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

  @Override
  public void reset() {
    setEntityId(defaultEntityId);
    resetAttributes();
    resetKeyStore(defaultEntityId, idpPrivateKey, idpCertificate);
    setAcsEndpoint(null);
    setAuthenticationMethod(this.defaultAuthenticationMethod);
    setSignatureAlgorithm(getDefaultSignatureAlgorithm());
  }

  private void resetAttributes() {
    attributes.clear();
    putAttribute("urn:mace:dir:attribute-def:uid", "john.doe");
    putAttribute("urn:mace:dir:attribute-def:cn", "John Doe");
    putAttribute("urn:mace:dir:attribute-def:givenName", "John");
    putAttribute("urn:mace:dir:attribute-def:sn", "Doe");
    putAttribute("urn:mace:dir:attribute-def:displayName", "John Doe");
    putAttribute("urn:mace:dir:attribute-def:mail", "j.doe@example.com");
    putAttribute("urn:mace:terena.org:attribute-def:schacHomeOrganization", "example.com");
    putAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName", "j.doe@example.com");
  }

  private void putAttribute(String key, String... values) {
    this.attributes.put(key, Arrays.asList(values));
  }

}
