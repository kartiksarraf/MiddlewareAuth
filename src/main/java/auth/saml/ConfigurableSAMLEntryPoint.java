package auth.saml;


import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ConfigurableSAMLEntryPoint extends SAMLEntryPoint {

    static Logger log = LoggerFactory.getLogger(ConfigurableSAMLEntryPoint.class);

    @Autowired
    private SAMLMessageHandler samlMessageHandler;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        org.opensaml.common.binding.SAMLMessageContext messageContext = null;
        try {
            messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, false, false);
        } catch (ValidationException | SecurityException | MessageDecodingException | MetadataProviderException ex) {
            ex.printStackTrace();
        }
        /*log.info("Saml Message Context {}", messageContext.toString());
        AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();
        log.info("Authn Request {}", authnRequest);*/
        super.commence(request, response, e);
    }

    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) throws MetadataProviderException {
        WebSSOProfileOptions profileOptions = super.getProfileOptions(context, exception);
        InTransport inboundMessageTransport = context.getInboundMessageTransport();
        if (inboundMessageTransport instanceof HttpServletRequestAdapter) {
            HttpServletRequestAdapter messageTransport = (HttpServletRequestAdapter) inboundMessageTransport;
            log.info("Entry Message Transport: {}", messageTransport.toString());
            log.info("User Agent: {}", messageTransport.getHeaderValue("User-Agent"));
            String forceAuthn = messageTransport.getParameterValue("force-authn");
            if ("true".equals(forceAuthn)) {
                profileOptions.setForceAuthN(true);
            }
        }
        return profileOptions;
    }
}