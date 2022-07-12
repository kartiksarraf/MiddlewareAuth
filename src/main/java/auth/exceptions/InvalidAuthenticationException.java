package auth.exceptions;

import org.springframework.security.core.AuthenticationException;

public class InvalidAuthenticationException extends AuthenticationException {

  /**
   * Custom exception for invalid auth
   *
   * @param msg
   */
  public InvalidAuthenticationException(String msg) {
    super(msg);
  }
}
