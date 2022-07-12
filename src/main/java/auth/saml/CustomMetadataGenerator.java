package auth.saml;

import auth.configurations.IdpConfiguration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.util.SAMLUtil;

import java.util.Collection;

import static auth.utils.SAMLBuilder.buildSAMLObject;

public class CustomMetadataGenerator extends MetadataGenerator {

    private String id;

    @Value("${idp.base_url}") String idpBaseUrl;

    @Autowired
    private IdpConfiguration idpConfiguration;

    @Override
    public EntityDescriptor generateMetadata() {
        boolean requestSigned = this.isRequestSigned();
        boolean assertionSigned = this.isWantAssertionSigned();
        Collection<String> includedNameID = this.getNameID();
        String entityId = this.getEntityId();
        String entityBaseURL = this.getEntityBaseURL();
        String entityAlias = this.getEntityAlias();
        this.validateRequiredAttributes(entityId, entityBaseURL);
        if (this.id == null) {
            this.id = SAMLUtil.getNCNameString(entityId);
        }

        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder)this.builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = (EntityDescriptor)builder.buildObject();
        if (this.id != null) {
            descriptor.setID(this.id);
        }

        descriptor.setEntityID(entityId);
        SPSSODescriptor ssoDescriptor = this.buildSPSSODescriptor(entityBaseURL, entityAlias, requestSigned, assertionSigned, includedNameID);
        IDPSSODescriptor idpssoDescriptor = null;
        if (ssoDescriptor != null) {
            descriptor.getRoleDescriptors().add(ssoDescriptor);
        }
        try {
            idpssoDescriptor = this.buildIDPSSODescriptor();
        } catch (SecurityException e) {
            e.printStackTrace();
        }
        if (idpssoDescriptor != null) {
            descriptor.getRoleDescriptors().add(idpssoDescriptor);
        }
        return descriptor;
    }

    public IDPSSODescriptor buildIDPSSODescriptor() throws SecurityException {
        Credential credential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(idpConfiguration.getEntityId())));

        IDPSSODescriptor idpssoDescriptor = buildSAMLObject(IDPSSODescriptor.class, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        /*NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        idpssoDescriptor.getNameIDFormats().add(nameIDFormat);*/

        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        SingleSignOnService singleSignOnService = buildSAMLObject(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
        singleSignOnService.setLocation(idpBaseUrl + "/SingleSignOnService");
        singleSignOnService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

        SingleLogoutService singleLogoutService = buildSAMLObject(SingleLogoutService.class, SingleLogoutService.DEFAULT_ELEMENT_NAME);
        singleLogoutService.setLocation(idpBaseUrl + "/SingleLogoutService");
        singleLogoutService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

        idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService);
        idpssoDescriptor.getSingleLogoutServices().add(singleLogoutService);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class, KeyDescriptor.DEFAULT_ELEMENT_NAME);
        encKeyDescriptor.setUse(UsageType.SIGNING);

        encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));

        idpssoDescriptor.getKeyDescriptors().add(encKeyDescriptor);

        return idpssoDescriptor;
    }
}
