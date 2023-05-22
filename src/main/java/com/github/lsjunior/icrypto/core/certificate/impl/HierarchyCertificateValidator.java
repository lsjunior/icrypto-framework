package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;

public class HierarchyCertificateValidator implements CertificateValidator, Serializable {

  public static final String VALIDATOR_NAME = "Hierarchy Validator";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private Collection<Certificate> certificates;

  public HierarchyCertificateValidator() {
    super();
  }

  public HierarchyCertificateValidator(final Certificate certificate) {
    super();
    this.certificates = Collections.singleton(certificate);
  }

  public HierarchyCertificateValidator(final Collection<Certificate> certificates) {
    super();
    this.certificates = certificates;
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    if (chain.size() < 2) {
      return Collections.singleton(
          new ValidationError(HierarchyCertificateValidator.VALIDATOR_NAME, "Certificate chain must be greater than 1(certificate and issuer certificate"));
    }
    List<ValidationError> list = new ArrayList<>();
    for (int i = 0; i < (chain.size() - 1); i++) {
      X509Certificate certificate = (X509Certificate) chain.get(i);
      X509Certificate issuer = (X509Certificate) chain.get(i + 1);

      try {
        certificate.verify(issuer.getPublicKey());

        int pathLen = issuer.getBasicConstraints();

        if (pathLen == -1) {
          list.add(new ValidationError(HierarchyCertificateValidator.VALIDATOR_NAME,
              "Certificate issuer '" + Certificates.toString(issuer.getSubjectX500Principal()) + "' is not a CA"));
        }

        boolean[] keyUsage = issuer.getKeyUsage();
        boolean keyCertSign = keyUsage[5];

        if (!keyCertSign) {
          list.add(new ValidationError(HierarchyCertificateValidator.VALIDATOR_NAME,
              "Certificate issuer '" + Certificates.toString(issuer.getSubjectX500Principal()) + "' dont have 'keyCertSign' in key usage"));
        }
      } catch (ICryptoException e) {
        ICryptoLog.getLogger().debug(e.getMessage(), e);
        list.add(
            new ValidationError(HierarchyCertificateValidator.VALIDATOR_NAME, "Certificate '" + Certificates.toString(certificate.getSubjectX500Principal())
                + "' not signed by '" + Certificates.toString(issuer.getSubjectX500Principal()) + "'"));
      } catch (Exception e) {
        throw new ICryptoException(e);
      }
    }

    try {
      if (this.certificates != null) {
        boolean requiredOk = false;
        outer: for (int i = 1; i < chain.size(); i++) {
          X509Certificate issuer = (X509Certificate) chain.get(i);
          for (Certificate required : this.certificates) {
            X509Certificate x509Required = (X509Certificate) required;
            if (Arrays.equals(issuer.getEncoded(), x509Required.getEncoded())) {
              ICryptoLog.getLogger().info("Matches " + Certificates.toString(x509Required.getSubjectX500Principal()));
              requiredOk = true;
              break outer;
            }
          }
        }

        if (!requiredOk) {
          list.add(
              new ValidationError(HierarchyCertificateValidator.VALIDATOR_NAME, "Certificate chain is invalid, a required certificate could not be found"));
        }
      }
    } catch (CertificateEncodingException e) {
      throw new ICryptoException(e);
    }

    return list;
  }
}
