package auth.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Controller
public class UserController {

  private List<Map<String, String>> samlAttributes;

  @Autowired
  @SuppressWarnings("unchecked")
  public UserController(ObjectMapper objectMapper) throws IOException {
    this.samlAttributes = objectMapper.readValue(new ClassPathResource("saml-attributes.json").getInputStream(), List.class);
  }

  /**
   * Default Landing Page of the application
   *
   * @param authentication
   * @return
   */
  @GetMapping("/")
  public String index(Authentication authentication) {
    return authentication == null ? "index" : "redirect:/user.html";
  }

  /**
   * User Page, when user successfully logged in the system
   *
   * @param authentication
   * @param modelMap
   * @return
   */
  @GetMapping("/user.html")
  public String user(Authentication authentication, ModelMap modelMap) {
    modelMap.addAttribute("user", authentication);
    return "user";
  }
}
