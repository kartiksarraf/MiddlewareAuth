package auth.controllers;

import auth.configurations.IdpConfiguration;
import auth.saml.SAMLMessageHandler;
import auth.models.SAMLAttribute;
import auth.models.SAMLPrincipal;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static auth.constants.SamlResponseAttributes.NAME;
import static auth.constants.SamlResponseAttributes.UID;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

@Controller
public class SsoController {

  static Logger log = LoggerFactory.getLogger(SsoController.class);

  @Autowired
  private SAMLMessageHandler samlMessageHandler;

  @Autowired
  private IdpConfiguration idpConfiguration;

  @Value("${appian.logout_url}")
  private String logoutUrl;

  /**
   * SingleSignOnService Get Controller (Start point for Appian environemnt Login)
   *
   * @param request
   * @param response
   * @param authentication
   * @throws IOException
   * @throws MarshallingException
   * @throws SignatureException
   * @throws MessageEncodingException
   * @throws ValidationException
   * @throws SecurityException
   * @throws MessageDecodingException
   * @throws MetadataProviderException
   * @throws ServletException
   */
  @GetMapping("/SingleSignOnService")
  public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
          throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
    doSSO(request, response, authentication, false);
  }

  /**
   * SingleSignOnService Post Controller (Start point for Appian environemnt Login)
   *
   * @param request
   * @param response
   * @param authentication
   * @throws IOException
   * @throws MarshallingException
   * @throws SignatureException
   * @throws MessageEncodingException
   * @throws ValidationException
   * @throws SecurityException
   * @throws MessageDecodingException
   * @throws MetadataProviderException
   * @throws ServletException
   */
  @PostMapping("/SingleSignOnService")
  public void singleLogoutServicePost(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
          throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
    doSSO(request, response, authentication, true);
  }

  /**
   * Login Handler
   *
   * @param request
   * @param response
   * @param authentication
   * @param postRequest
   * @throws ValidationException
   * @throws SecurityException
   * @throws MessageDecodingException
   * @throws MarshallingException
   * @throws SignatureException
   * @throws MessageEncodingException
   * @throws MetadataProviderException
   * @throws IOException
   * @throws ServletException
   */
  private void doSSO(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest) throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException, IOException, ServletException {
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, postRequest, false);
    log.info("Saml Message Context {}", messageContext.toString());
    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    String assertionConsumerServiceURL = idpConfiguration.getAcsEndpoint() != null ? idpConfiguration.getAcsEndpoint() : authnRequest.getAssertionConsumerServiceURL();
    List<SAMLAttribute> attributes = attributes(authentication);

    SAMLPrincipal principal = new SAMLPrincipal(
            authentication.getName(),
            attributes.stream()
                    .filter(attr -> "urn:oasis:names:tc:SAML:1.1:nameid-format".equals(attr.getName()))
                    .findFirst().map(attr -> attr.getValue()).orElse(NameIDType.EMAIL),
            attributes,
            authnRequest.getIssuer().getValue(),
            authnRequest.getID(),
            assertionConsumerServiceURL,
            messageContext.getRelayState());

    samlMessageHandler.sendAuthnResponse(principal, response);
  }

  /**
   * Set Attributes for SAML Response
   *
   * @param authentication
   * @return
   */
  private List<SAMLAttribute> attributes(Authentication authentication) {
    String uid = authentication.getName();
    Object principalObject =  authentication.getPrincipal();
    Object details = authentication.getDetails();

    log.info("Auth Principal {}", principalObject);
    log.info("Auth Details {}", details);

    Map<String, List<String>> result = new HashMap<>(idpConfiguration.getAttributes());

    //Provide the ability to limit the list attributes returned to the SP
    return result.entrySet().stream()
            .filter(entry -> !entry.getValue().stream().allMatch(StringUtils::isEmpty))
            .map(entry -> {
              switch(entry.getKey()) {
                case UID:
                case NAME:
                  return new SAMLAttribute(entry.getKey(), singletonList(uid));
                default:
                  return new SAMLAttribute(entry.getKey(), entry.getValue());
              }
            })
            .collect(toList());
  }

  /**
   * Logout Handler (Future Use)
   *
   * @param request
   * @param response
   * @param authentication
   * @param postRequest
   * @throws ValidationException
   * @throws MessageDecodingException
   * @throws SecurityException
   * @throws MetadataProviderException
   * @throws MessageEncodingException
   * @throws IOException
   * @throws ServletException
   */
  private void doLogout(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest) throws ValidationException, MessageDecodingException, SecurityException, MetadataProviderException, MessageEncodingException, IOException, ServletException {
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, postRequest, true);
    log.info("Saml Message Context {}", messageContext);

    LogoutRequest logoutRequest = (LogoutRequest) messageContext.getInboundSAMLMessage();
    samlMessageHandler.sendLogoutResponse(logoutRequest, response, logoutUrl);
  }

}
