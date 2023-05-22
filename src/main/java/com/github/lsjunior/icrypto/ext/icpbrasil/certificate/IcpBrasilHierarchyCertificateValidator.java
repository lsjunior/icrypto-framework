package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;
import com.github.lsjunior.icrypto.core.certificate.impl.PkixCertificateValidator;

public class IcpBrasilHierarchyCertificateValidator implements CertificateValidator, Serializable {

  public static final String VALIDATOR_NAME = "Hierarchy Validator";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private CertificateValidator delegate;

  public IcpBrasilHierarchyCertificateValidator() throws IOException {
    super();
    Collection<Certificate> certificates = IcpBrasilHierarchyDownloader.getCertificates().values();
    this.init(certificates);
  }

  public IcpBrasilHierarchyCertificateValidator(final URL url) throws IOException {
    super();
    Collection<Certificate> certificates = IcpBrasilHierarchyDownloader.getCertificates(url).values();
    this.init(certificates);
  }

  public IcpBrasilHierarchyCertificateValidator(final InputStream inputStream) throws IOException {
    super();
    Collection<Certificate> certificates = IcpBrasilHierarchyDownloader.getCertificates(inputStream).values();
    this.init(certificates);
  }

  private void init(final Collection<Certificate> certificates) {
    this.delegate = new PkixCertificateValidator(certificates, null);
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    return this.delegate.validate(chain);
  }
}
