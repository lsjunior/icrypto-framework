package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;

public class DateCertificateValidator implements CertificateValidator, Serializable {

  public static final String VALIDATOR_NAME = "Date Validator";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private Date date;

  public DateCertificateValidator() {
    super();
  }

  public DateCertificateValidator(final Date date) {
    super();
    this.date = date;
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    try {
      X509Certificate x509Certificate = (X509Certificate) chain.get(0);
      Date current = null;

      if (this.date == null) {
        current = new Date();
      } else {
        current = this.date;
      }

      x509Certificate.checkValidity(current);

      return Collections.emptyList();
    } catch (CertificateExpiredException e) {
      ICryptoLog.getLogger().debug(e.getMessage(), e);
      ValidationError error = new ValidationError(DateCertificateValidator.VALIDATOR_NAME, "Certificate expired");
      return Collections.singleton(error);
    } catch (CertificateNotYetValidException e) {
      ICryptoLog.getLogger().debug(e.getMessage(), e);
      ValidationError error = new ValidationError(DateCertificateValidator.VALIDATOR_NAME, "Certificate not yet valid");
      return Collections.singleton(error);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }
}
