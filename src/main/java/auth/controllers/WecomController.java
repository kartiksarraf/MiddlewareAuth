package auth.controllers;

import auth.utils.HttpRequestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(path = "/wecom")
public class WecomController {

  @Value("${appian.login_url}")
  private String loginUrl;

  @Value("${wecom.access_token_url}")
  private String wecomAccessTokenUrl;

  private static final String CLIENT_ID = "client_id";
  private static final String CLIENT_SECRET = "client_secret";
  private static final String GRANT_TYPE = "grant_type";
  private static final String CODE = "code";
  private static final String AUTHORIZATION_CODE = "authorization_code";


  static Logger log = LoggerFactory.getLogger(WecomController.class);

  /**
   * authentication Page of the WECOM
   *
   * @param code
   * @return
   */
  @GetMapping("/authorize/{code}")
  @ResponseBody
  public ResponseEntity<Void> authorize(@PathVariable String code) throws IOException {
    log.info("Got Wecom Authorize request with code {}", code);
    Object result = this.getWecomAccessToken(code);
    return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(loginUrl)).build();
  }

  @RequestMapping("/test")
  public String test() {
    return "12";
  }

  private Object getWecomAccessToken(String code) throws IOException {

    Map<String, String> parameters = new HashMap<>();
    /**
     * https://app1-qa.wfp.shenfutech.com/oauth2/token?client_id={}&client_secret={}&grant_type=authorization_code&code={}
     */
    parameters.put(CLIENT_ID, "1000044");
    parameters.put(CLIENT_SECRET, "I_w_gIc0hss1THD3gg5hMDe1BqPagXMYzfqQf9OUlgY");
    parameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
    parameters.put(CODE, code);
    return HttpRequestUtils.createHttpRequest(wecomAccessTokenUrl, parameters);

  }
}
