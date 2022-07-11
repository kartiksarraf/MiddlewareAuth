package auth.configurations;

import auth.saml.*;
import auth.utils.KeyStoreLocator;
import auth.utils.ProxiedSAMLContextProviderLB;
import auth.utils.UpgradedSAMLBootstrap;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.decoding.URIComparator;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.Filter;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig implements WebMvcConfigurer {

    @Value("${secure_cookie}")
    private boolean secureCookie;

    /**
     * Bean for SAML Message handler: use for sending saml messages (request and response)
     *
     * @param clockSkew
     * @param expires
     * @param idpBaseUrl
     * @param compareEndpoints
     * @param idpConfiguration
     * @param keyManager
     * @return
     * @throws XMLParserException
     * @throws URISyntaxException
     */
    @Bean
    @Autowired
    public SAMLMessageHandler samlMessageHandler(@Value("${idp.clock_skew}") int clockSkew,
                                                 @Value("${idp.expires}") int expires,
                                                 @Value("${idp.base_url}") String idpBaseUrl,
                                                 @Value("${idp.compare_endpoints}") boolean compareEndpoints,
                                                 IdpConfiguration idpConfiguration,
                                                 JKSKeyManager keyManager)
            throws XMLParserException, URISyntaxException {
        StaticBasicParserPool parserPool = new StaticBasicParserPool();
        BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();
        securityPolicy.getPolicyRules().addAll(Arrays.asList(new IssueInstantRule(clockSkew, expires)));

        HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder = new HTTPRedirectDeflateDecoder(parserPool);
        HTTPPostDecoder httpPostDecoder = new HTTPPostDecoder(parserPool);
        if (!compareEndpoints) {
            URIComparator noopComparator = (uri1, uri2) -> true;
            httpPostDecoder.setURIComparator(noopComparator);
            httpRedirectDeflateDecoder.setURIComparator(noopComparator);
        }

        parserPool.initialize();
        HTTPPostSimpleSignEncoder httpPostSimpleSignEncoder = new HTTPPostSimpleSignEncoder(VelocityFactory.getEngine(), "/templates/saml2-post-simplesign-binding.vm", true);

        return new SAMLMessageHandler(
                keyManager,
                Arrays.asList(httpRedirectDeflateDecoder, httpPostDecoder),
                httpPostSimpleSignEncoder,
                new StaticSecurityPolicyResolver(securityPolicy),
                idpConfiguration,
                idpBaseUrl);
    }

    /**
     * Saml Bootstrap Bean
     *
     * @return
     */
    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new UpgradedSAMLBootstrap();
    }

    /**
     * Set Key Manager using JKSKeyManager
     *
     * @param idpEntityId
     * @param idpPrivateKey
     * @param idpCertificate
     * @param idpPassphrase
     * @return
     * @throws InvalidKeySpecException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws XMLStreamException
     */
    @Autowired
    @Bean
    public JKSKeyManager keyManager(@Value("${idp.entity_id}") String idpEntityId,
                                    @Value("${idp.private_key}") String idpPrivateKey,
                                    @Value("${idp.certificate}") String idpCertificate,
                                    @Value("${idp.passphrase}") String idpPassphrase) throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
        KeyStore keyStore = KeyStoreLocator.createKeyStore(idpPassphrase);
        KeyStoreLocator.addPrivateKey(keyStore, idpEntityId, idpPrivateKey, idpCertificate, idpPassphrase);
        return new JKSKeyManager(keyStore, Collections.singletonMap(idpEntityId, idpPassphrase), idpEntityId);
    }

    @Configuration
    protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {

        @Value("${sp.idp_metadata_url}")
        private String identityProviderMetadataUrl;

        @Value("${sp.base_url}")
        private String spBaseUrl;

        @Value("${sp.entity_id}")
        private String spEntityId;

        @Value("${sp.acs_location_path}")
        private String assertionConsumerServiceURLPath;

        @Value("${sp.logout_path}")
        private String logoutURLPath;

        @Value("${sp.single_logout_path}")
        private String singleLogoutURLPath;

        @Value("${appian.logout_url}")
        private String appianLogoutUrl;

        @Value("${azure.logout_url}")
        private String azureLogoutUrl;

        @Autowired
        private IdpConfiguration idpConfiguration;

        @Autowired
        private SAMLMessageHandler samlMessageHandler;

        @Autowired
        JKSKeyManager keyManager;

        private DefaultResourceLoader defaultResourceLoader = new DefaultResourceLoader();

        /**
         * SAML Authentication Filter, if config for auth success and failure
         *
         * @return
         * @throws Exception
         */
        private SAMLAttributeAuthenticationFilter authenticationFilter() throws Exception {
            SAMLAttributeAuthenticationFilter filter = new SAMLAttributeAuthenticationFilter();
            filter.setAuthenticationManager(authenticationManagerBean());
            filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true"));
            return filter;
        }

        @Bean
        public SAMLAuthenticationProvider samlAuthenticationProvider() {
            SAMLAuthenticationProvider samlAuthenticationProvider = new RoleSAMLAuthenticationProvider();
            samlAuthenticationProvider.setUserDetails(new DefaultSAMLUserDetailsService());
            samlAuthenticationProvider.setForcePrincipalAsString(false);
            samlAuthenticationProvider.setExcludeCredential(true);
            return samlAuthenticationProvider;
        }

        @Bean
        public SAMLEntryPoint samlEntryPoint() {
            WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
            webSSOProfileOptions.setIncludeScoping(false);

            SAMLEntryPoint samlEntryPoint = new ConfigurableSAMLEntryPoint();
            samlEntryPoint.setFilterProcessesUrl("login");
            samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
            return samlEntryPoint;
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            super.configure(web);
            web.ignoring().antMatchers("/internal/**");
        }

        /**
         * Main Configure bean for spring security ##### VERY IMPORTANT #####
         *
         * @param http
         * @throws Exception
         */
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/", "/metadata", "/favicon.ico", "/api/**", "/*.css", "/*.js", azureLogoutUrl + "/**").permitAll()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().hasRole("USER")
                    .and()
                    .httpBasic().authenticationEntryPoint(samlEntryPoint())
                    .and()
                    .csrf().disable()
                    .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class) /* For Custom SP */
                    .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class) /* For Custom IDP */
                    .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
                    .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/SingleLogoutService"))
                    .addLogoutHandler((request, response, authentication) -> {
                        try {
                            response.sendRedirect(logoutURLPath);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
        }

        /**
         * Success redirect handler: when auth is successful from actual azure ad,
         * then user prompt to user.html
         *
         * @return
         */
        @Bean
        public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
            SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                    new SavedRequestAwareAuthenticationSuccessHandler();
            successRedirectHandler.setDefaultTargetUrl("/user.html");
            return successRedirectHandler;
        }

        /**
         * Configure application that user two authentication providers
         * 1. samlAuthenticationProvider: Work As A SP (send auth request to actual Azure AD)
         * 2. CustomAuthenticationProvider: Work as A IDP (send auth response to actual sp: appian env)
         *
         * @param auth
         */
        @Override
        public void configure(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(samlAuthenticationProvider());
            auth.authenticationProvider(new CustomAuthenticationProvider(idpConfiguration));
        }

        /**
         * Authentication manager bean
         *
         * @return
         * @throws Exception
         */
        @Bean
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

        @Bean
        public MetadataDisplayFilter metadataDisplayFilter() {
            DefaultMetadataDisplayFilter displayFilter = new DefaultMetadataDisplayFilter();
            displayFilter.setFilterProcessesUrl("metadata");
            return displayFilter;
        }

        /**
         * Authentication Failure Handler Bean
         *
         * @return
         */
        @Bean
        public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
            SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
            failureHandler.setUseForward(true);
            failureHandler.setDefaultFailureUrl("/error");
            return failureHandler;
        }

        @Bean
        public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
            SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
            /*samlWebSSOProcessingFilter.setFilterProcessesUrl("saml/SSO");*/
            samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
            samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
            samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
            return samlWebSSOProcessingFilter;
        }

        @Bean
        public MetadataGeneratorFilter metadataGeneratorFilter() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
            return new MetadataGeneratorFilter(metadataGenerator());
        }

        @Bean
        public SingleLogoutProfile logoutProfile() {
            return new SingleLogoutProfileImpl();
        }

        /**
         * SuccessLogoutHandler Bean:
         * After successfully logout from this application,
         * it should redirect to azure portal for logout there,
         * After azure logout it should redirect to Appian login page
         *
         * @return
         * @throws UnsupportedEncodingException
         */
        @Bean
        public SimpleUrlLogoutSuccessHandler successLogoutHandler() throws UnsupportedEncodingException {
            SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
            /* Logout From Azure AD */
            String endSessionEndpoint = this.azureLogoutUrl;
            successLogoutHandler.setDefaultTargetUrl(endSessionEndpoint + "?post_logout_redirect_uri=" +
                    URLEncoder.encode(appianLogoutUrl, "UTF-8"));
            return successLogoutHandler;
        }

        /**
         * Logout Handler Bean:
         * Clear authentication and invalidate cache for this application session
         *
         * @return
         */
        @Bean
        public SecurityContextLogoutHandler logoutHandler() {
            SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
            logoutHandler.setInvalidateHttpSession(true);
            logoutHandler.setClearAuthentication(true);
            return logoutHandler;
        }

        /**
         * Logout Processing Filter Bean
         *
         * @return
         * @throws UnsupportedEncodingException
         */
        @Bean
        public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() throws UnsupportedEncodingException {
            return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
        }

        /**
         * Saml Logout Filter bean: Execute when "logoutURLPath" is called
         *
         * @return
         * @throws UnsupportedEncodingException
         */
        @Bean
        public SAMLLogoutFilter samlLogoutFilter() throws UnsupportedEncodingException {
            return new SAMLLogoutFilter(successLogoutHandler(),
                    new LogoutHandler[] { logoutHandler() },
                    new LogoutHandler[] { logoutHandler() });
        }

        /**
         * AddFilterAfter bean:
         * After login to application we have filters for redirect urls to correct filters/processes
         *
         * @return
         * @throws Exception
         */
        @Bean
        public FilterChainProxy samlFilter() throws Exception {
            List<SecurityFilterChain> chains = new ArrayList<>();
            chains.add(chain("/login/**", samlEntryPoint()));
            chains.add(chain("/metadata/**", metadataDisplayFilter()));
            chains.add(chain(assertionConsumerServiceURLPath + "/**", samlWebSSOProcessingFilter()));
            chains.add(chain(logoutURLPath + "/**", samlLogoutFilter()));
            chains.add(chain(singleLogoutURLPath + "/**", samlLogoutProcessingFilter()));
            return new FilterChainProxy(chains);
        }

        private DefaultSecurityFilterChain chain(String pattern, Filter entryPoint) {
            return new DefaultSecurityFilterChain(new AntPathRequestMatcher(pattern), entryPoint);
        }

        @Bean
        public ExtendedMetadata extendedMetadata() {
            ExtendedMetadata extendedMetadata = new ExtendedMetadata();
            extendedMetadata.setIdpDiscoveryEnabled(false);
            extendedMetadata.setSignMetadata(true);
            return extendedMetadata;
        }

        @Bean
        public MetadataProvider identityProvider() throws MetadataProviderException, XMLParserException {
            Resource resource = defaultResourceLoader.getResource(identityProviderMetadataUrl);
            ResourceMetadataProvider resourceMetadataProvider = new ResourceMetadataProvider(resource);
            resourceMetadataProvider.setParserPool(parserPool());
            ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(resourceMetadataProvider, extendedMetadata());
            extendedMetadataDelegate.setMetadataTrustCheck(true);
            extendedMetadataDelegate.setMetadataRequireSignature(true);
            return extendedMetadataDelegate;
        }

        @Bean
        @Qualifier("metadata")
        public CachingMetadataManager metadata() throws MetadataProviderException, XMLParserException {
            List<MetadataProvider> providers = new ArrayList<>();
            providers.add(identityProvider());

            return new CachingMetadataManager(providers);
        }

        @Bean
        public VelocityEngine velocityEngine() {
            return VelocityFactory.getEngine();
        }

        @Bean(initMethod = "initialize")
        public ParserPool parserPool() {
            return new StaticBasicParserPool();
        }

        @Bean(name = "parserPoolHolder")
        public ParserPoolHolder parserPoolHolder() {
            return new ParserPoolHolder();
        }

        @Bean
        public SAMLContextProvider contextProvider() throws URISyntaxException {
            return new ProxiedSAMLContextProviderLB(new URI(spBaseUrl));
        }

        @Bean
        public MetadataGenerator metadataGenerator() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
            MetadataGenerator metadataGenerator = new CustomMetadataGenerator();
            metadataGenerator.setEntityId(spEntityId);
            metadataGenerator.setEntityBaseURL(spBaseUrl);
            metadataGenerator.setExtendedMetadata(extendedMetadata());
            metadataGenerator.setIncludeDiscoveryExtension(false);
            metadataGenerator.setKeyManager(keyManager);
            return metadataGenerator;
        }
    }

}
