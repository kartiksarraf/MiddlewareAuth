package idp.utils;

import org.springframework.security.saml.context.SAMLContextProviderLB;

import java.net.URI;

public class ProxiedSAMLContextProviderLB extends SAMLContextProviderLB {

  public ProxiedSAMLContextProviderLB(URI uri) {
    super();
    setServerName(uri.getHost());
    setScheme(uri.getScheme());
    setContextPath("");
    if (uri.getPort() > 0) {
      setIncludeServerPortInRequestURL(true);
      setServerPort(uri.getPort());
    }
  }

}
