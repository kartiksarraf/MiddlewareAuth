package auth.utils;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

public class KeyStoreLocator {

  private static final CertificateFactory certificateFactory;

  static {
    try {
      certificateFactory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Create key store using pass phrase
   *
   * @param pemPassPhrase
   * @return
   */
  public static KeyStore createKeyStore(String pemPassPhrase) {
    try {
      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(null, pemPassPhrase.toCharArray());
      return keyStore;
    } catch (Exception e) {
      //too many exceptions we can't handle, so brute force catch
      throw new RuntimeException(e);
    }
  }

  /**
   * Add private key in keystore
   * PrivateKey must be in the DER unencrypted PKCS#8 format.
   *
   * @param keyStore
   * @param alias
   * @param privateKey
   * @param certificate
   * @param password
   * @throws IOException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws KeyStoreException
   * @throws CertificateException
   */
  public static void addPrivateKey(KeyStore keyStore, String alias, String privateKey, String certificate, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
    String wrappedCert = wrapCert(certificate);
    byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());

    char[] passwordChars = password.toCharArray();
    Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes()));
    ArrayList<Certificate> certs = new ArrayList<>();
    certs.add(cert);

    byte[] privKeyBytes = IOUtils.toByteArray(new ByteArrayInputStream(decodedKey));

    KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
    RSAPrivateKey privKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(ks);
    keyStore.setKeyEntry(alias, privKey, passwordChars, certs.toArray(new Certificate[certs.size()]));
  }

  /**
   * Wrap certificate using prefix: BEGIN CERT.., and suffix: END Cert.
   *
   * @param certificate
   * @return
   */
  private static String wrapCert(String certificate) {
    return "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----";
  }

}
