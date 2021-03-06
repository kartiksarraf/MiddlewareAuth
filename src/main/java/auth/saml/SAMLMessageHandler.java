package auth.saml;

import auth.configurations.IdpConfiguration;
import auth.utils.ProxiedSAMLContextProviderLB;
import auth.utils.SAMLBuilder;
import auth.models.SAMLPrincipal;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;

import static auth.utils.SAMLBuilder.*;
import static java.util.Arrays.asList;
import static org.opensaml.xml.Configuration.getValidatorSuite;

public class SAMLMessageHandler {

  static Logger log = LoggerFactory.getLogger(SAMLMessageHandler.class);

  private final KeyManager keyManager;
  private final Collection<SAMLMessageDecoder> decoders;
  private final SAMLMessageEncoder encoder;
  private final SecurityPolicyResolver resolver;
  private final IdpConfiguration idpConfiguration;

  private final List<ValidatorSuite> validatorSuites;
  private final ProxiedSAMLContextProviderLB proxiedSAMLContextProviderLB;

  /**
   * Constructor
   *
   * @param keyManager
   * @param decoders
   * @param encoder
   * @param securityPolicyResolver
   * @param idpConfiguration
   * @param idpBaseUrl
   * @throws URISyntaxException
   */
  public SAMLMessageHandler(KeyManager keyManager, Collection<SAMLMessageDecoder> decoders,
                            SAMLMessageEncoder encoder, SecurityPolicyResolver securityPolicyResolver,
                            IdpConfiguration idpConfiguration, String idpBaseUrl) throws URISyntaxException {
    this.keyManager = keyManager;
    this.encoder = encoder;
    this.decoders = decoders;
    this.resolver = securityPolicyResolver;
    this.idpConfiguration = idpConfiguration;
    this.validatorSuites = asList(
            getValidatorSuite("saml2-core-schema-validator"),
            getValidatorSuite("saml2-core-spec-validator"));
    this.proxiedSAMLContextProviderLB = new ProxiedSAMLContextProviderLB(new URI(idpBaseUrl));
  }

  /**
   * Extract SAML Message from servlet request and response
   *
   * @param request
   * @param response
   * @param postRequest
   * @param isLogoutRequest
   * @return
   * @throws ValidationException
   * @throws SecurityException
   * @throws MessageDecodingException
   * @throws MetadataProviderException
   */
  public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request, HttpServletResponse response,
                                                      boolean postRequest, boolean isLogoutRequest) throws ValidationException, SecurityException, MessageDecodingException, MetadataProviderException {
    SAMLMessageContext messageContext = new SAMLMessageContext();

    proxiedSAMLContextProviderLB.populateGenericContext(request, response, messageContext);

    messageContext.setSecurityPolicyResolver(resolver);

    SAMLMessageDecoder samlMessageDecoder = samlMessageDecoder(postRequest);
    samlMessageDecoder.decode(messageContext);

    SAMLObject inboundSAMLMessage = messageContext.getInboundSAMLMessage();

    if (isLogoutRequest) {
      LogoutRequest logoutRequest = (LogoutRequest) inboundSAMLMessage;
      //lambda is poor with Exceptions
      for (ValidatorSuite validatorSuite : validatorSuites) {
        validatorSuite.validate(logoutRequest);
      }
      return messageContext;
    }

    AuthnRequest authnRequest = (AuthnRequest) inboundSAMLMessage;
    //lambda is poor with Exceptions
    for (ValidatorSuite validatorSuite : validatorSuites) {
      validatorSuite.validate(authnRequest);
    }
    return messageContext;
  }

  /**
   * Decode SAML Message that comes in request/response using SAMLMessageDecoder depends on binding
   *
   * @param postRequest
   * @return
   */
  private SAMLMessageDecoder samlMessageDecoder(boolean postRequest) {
    return decoders.stream().filter(samlMessageDecoder -> postRequest ?
                    samlMessageDecoder.getBindingURI().equals(SAMLConstants.SAML2_POST_BINDING_URI) :
                    samlMessageDecoder.getBindingURI().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI))
            .findAny()
            .orElseThrow(() -> new RuntimeException(String.format("Only %s and %s are supported",
                    SAMLConstants.SAML2_REDIRECT_BINDING_URI,
                    SAMLConstants.SAML2_POST_BINDING_URI)));
  }

  /**
   * Send Auth Response when user able to login successfully using principal and response
   *
   * @param principal
   * @param response
   * @throws MarshallingException
   * @throws SignatureException
   * @throws MessageEncodingException
   */
  @SuppressWarnings("unchecked")
  public void sendAuthnResponse(SAMLPrincipal principal, HttpServletResponse response) throws MarshallingException, SignatureException, MessageEncodingException {
    log.info("Sending auth response for requestId {}", principal.getRequestID());
    Status status = buildStatus(StatusCode.SUCCESS_URI);

    String entityId = idpConfiguration.getEntityId();
    Credential signingCredential = resolveCredential(entityId);

    Response authResponse = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);
    Issuer issuer = buildIssuer(entityId);

    authResponse.setIssuer(issuer);
    authResponse.setID(SAMLBuilder.randomSAMLId());
    authResponse.setIssueInstant(new DateTime());
    authResponse.setInResponseTo(principal.getRequestID());

    Assertion assertion = buildAssertion(principal, status, entityId);
    signAssertion(assertion, signingCredential);

    authResponse.getAssertions().add(assertion);
    authResponse.setDestination(principal.getAssertionConsumerServiceURL());

    authResponse.setStatus(status);

    Endpoint endpoint = buildSAMLObject(Endpoint.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    endpoint.setLocation(principal.getAssertionConsumerServiceURL());

    HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

    BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();

    messageContext.setOutboundMessageTransport(outTransport);
    messageContext.setPeerEntityEndpoint(endpoint);
    messageContext.setOutboundSAMLMessage(authResponse);
//    messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);

    messageContext.setOutboundMessageIssuer(entityId);
    messageContext.setRelayState(principal.getRelayState());

    encoder.encode(messageContext);
  }

  /**
   * Send Logout Response when user able to logout successfully using principal and response
   *
   * @param logoutRequest
   * @param response
   * @param logoutUrl
   * @throws MessageEncodingException
   */
  public void sendLogoutResponse(LogoutRequest logoutRequest, HttpServletResponse response, String logoutUrl) throws MessageEncodingException {
    log.info("Sending logout response for requestId {}", logoutRequest.getID());
    Status status = buildStatus(StatusCode.SUCCESS_URI);

    String entityId = idpConfiguration.getEntityId();

    Issuer issuer = buildIssuer(entityId);
    LogoutResponse logoutResponse = buildSAMLObject(LogoutResponse.class, LogoutResponse.DEFAULT_ELEMENT_NAME);

    logoutResponse.setIssuer(issuer);
    logoutResponse.setID(SAMLBuilder.randomSAMLId());
    logoutResponse.setIssueInstant(new DateTime());
    logoutResponse.setInResponseTo(logoutRequest.getID());
    logoutResponse.setDestination(logoutUrl);
    logoutResponse.setStatus(status);

    Endpoint endpoint = buildSAMLObject(Endpoint.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
    endpoint.setLocation(logoutUrl);

    HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

    BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();

    messageContext.setOutboundMessageTransport(outTransport);
    messageContext.setPeerEntityEndpoint(endpoint);
    messageContext.setOutboundSAMLMessage(logoutResponse);

    messageContext.setOutboundMessageIssuer(entityId);
    encoder.encode(messageContext);
  }

  /**
   * Resolve credential using entityId
   *
   * @param entityId
   * @return
   */
  private Credential resolveCredential(String entityId) {
    try {
      return keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));
    } catch (SecurityException e) {
      throw new RuntimeException(e);
    }
  }

}
