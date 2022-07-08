package auth.controller;

import auth.config.IdpConfiguration;
import auth.saml.SAMLMessageHandler;
import auth.utils.SAMLAttribute;
import auth.utils.SAMLPrincipal;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

@Controller
public class SsoController {

  static Logger log = LoggerFactory.getLogger(SsoController.class);

  @Autowired
  private SAMLMessageHandler samlMessageHandler;

  @Autowired
  private IdpConfiguration idpConfiguration;

  @GetMapping("/SingleSignOnService")
  public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
          throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
    doSSO(request, response, authentication, false);
  }

  @PostMapping("/SingleSignOnService")
  public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
          throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
    doSSO(request, response, authentication, true);
  }

  @SuppressWarnings("unchecked")
  private void doSSO(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest) throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException, IOException, ServletException {
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, postRequest);
    log.info("Saml Message Context {}", messageContext);
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

  @SuppressWarnings("unchecked")
  private List<SAMLAttribute> attributes(Authentication authentication) {
    String uid = authentication.getName();
    Object principalObject =  authentication.getPrincipal();
    Object details = authentication.getDetails();

    log.info("Auth Principal {}", principalObject);
    log.info("Auth Details {}", details);

    Map<String, List<String>> result = new HashMap<>(idpConfiguration.getAttributes());

   /* Optional<Map<String, List<String>>> optionalMap = idpConfiguration.getUsers().stream()
            .filter(user -> user.getPrincipal().equals(uid))
            .findAny()
            .map(FederatedUserAuthenticationToken::getAttributes);
    optionalMap.ifPresent(result::putAll);

    //See SAMLAttributeAuthenticationFilter#setDetails
    Map<String, String[]> parameterMap = (Map<String, String[]>) authentication.getDetails();
    parameterMap.forEach((key, values) -> {
      result.put(key, Arrays.asList(values));
    });*/

    //Provide the ability to limit the list attributes returned to the SP
    return result.entrySet().stream()
            .filter(entry -> !entry.getValue().stream().allMatch(StringUtils::isEmpty))
            .map(entry -> {
              switch(entry.getKey()) {
                case "urn:mace:dir:attribute-def:uid":
                case "urn:mace:dir:attribute-def:givenName":
                  return new SAMLAttribute(entry.getKey(), singletonList(uid));
                default:
                  return new SAMLAttribute(entry.getKey(), entry.getValue());
              }
            })
            .collect(toList());
  }

}
