package auth.saml;

import auth.configurations.SpConfiguration;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;

import java.util.Collection;

public class ConfigurableSAMLProcessor extends SAMLProcessorImpl {

    private final SpConfiguration spConfiguration;

    public ConfigurableSAMLProcessor(Collection<SAMLBinding> bindings, SpConfiguration spConfiguration) {
        super(bindings);
        this.spConfiguration = spConfiguration;
    }

    @Override
    public SAMLMessageContext sendMessage(SAMLMessageContext samlContext, boolean sign)
            throws SAMLException, MetadataProviderException, MessageEncodingException {

        Endpoint endpoint = samlContext.getPeerEntityEndpoint();

        SAMLBinding binding = getBinding(endpoint);

        /*NameID nameID = buildSAMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue("kartiks@appcinotechnologies676.onmicrosoft.com");
        nameID.setFormat(NameIDType.EMAIL);

        Subject subject = buildSAMLObject(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID(nameID);*/

        samlContext.setLocalEntityId(spConfiguration.getEntityId());
        samlContext.getLocalEntityMetadata().setEntityID(spConfiguration.getEntityId());
        samlContext.getPeerEntityEndpoint().setLocation(spConfiguration.getIdpSSOServiceURL());
        /*AuthnRequest authnRequest = (AuthnRequest) samlContext.getOutboundSAMLMessage();
        authnRequest.setSubject(subject);
        samlContext.setOutboundSAMLMessage(authnRequest);*/

        SPSSODescriptor roleDescriptor = (SPSSODescriptor) samlContext.getLocalEntityMetadata().getRoleDescriptors().get(0);
        AssertionConsumerService assertionConsumerService = roleDescriptor.getAssertionConsumerServices().stream().filter(service -> service.isDefault()).findAny().orElseThrow(() -> new RuntimeException("No default ACS"));
        assertionConsumerService.setBinding(spConfiguration.getProtocolBinding());
        assertionConsumerService.setLocation(spConfiguration.getAssertionConsumerServiceURL());

        return super.sendMessage(samlContext, spConfiguration.isNeedsSigning(), binding);
    }
}
