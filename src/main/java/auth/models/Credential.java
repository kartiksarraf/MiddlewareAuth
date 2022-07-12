package auth.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.io.Serializable;

/**
 * Credential POJO Class
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Credential implements Serializable {

  private String certificate;
  private String key;

}
