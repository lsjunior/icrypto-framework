package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.type.ProviderType;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.crl.impl.SimpleCrlProvider;
import com.github.lsjunior.icrypto.core.crl.util.Crls;
import com.google.common.base.Strings;

public class PkixCertificateValidator implements CertificateValidator, Serializable {

  public static final String VALIDATOR_NAME = "PKIX Validator";

  protected static final String CERTSTORE_TYPE = "Collection";

  protected static final String CERTPATH_TYPE = "PKIX";

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private Collection<Certificate> trustCaCerts;

  private Collection<Certificate> trustCerts;

  // http://docs.oracle.com/javase/1.5.0/docs/guide/security/pki-tiger.html
  private static final String OSCP_ENABLE_PROPERTY = "ocsp.enable";

  private static final String OSCP_ENABLE_VALUE = "true";

  private boolean revocationEnabled;

  private String provider;

  private CrlProvider crlProvider;

  public PkixCertificateValidator() {
    super();
  }

  public PkixCertificateValidator(final String provider) {
    super();
    try {
      this.provider = provider;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public PkixCertificateValidator(final Collection<Certificate> certificates, final String provider) {
    super();
    try {
      this.trustCaCerts = new ArrayList<>();
      this.trustCerts = new ArrayList<>();
      this.provider = provider;

      if (certificates != null) {
        for (Certificate certificate : certificates) {
          if (Certificates.isSelfSigned(certificate)) {
            this.trustCaCerts.add(certificate);
          } else {
            this.trustCerts.add(certificate);
          }
        }
      }
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public PkixCertificateValidator(final Collection<Certificate> trustCaCerts, final Collection<Certificate> trustCerts, final String provider) {
    super();
    this.trustCaCerts = trustCaCerts;
    this.trustCerts = trustCerts;
    this.provider = provider;
  }

  public boolean isRevocationEnabled() {
    return this.revocationEnabled;
  }

  public void setRevocationEnabled(final boolean revocationEnabled) {
    this.revocationEnabled = revocationEnabled;
  }

  public CrlProvider getCrlProvider() {
    return this.crlProvider;
  }

  public void setCrlProvider(final CrlProvider crlProvider) {
    this.crlProvider = crlProvider;
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    try {
      this.getValidatorResult(chain);
      return Collections.emptyList();
    } catch (CertPathBuilderException e) {
      ICryptoLog.getLogger().info(e.getMessage(), e);
      ICryptoLog.getLogger().info("Validation error: " + e.getMessage());

      String msg = "Invalid certificate infrastructure";
      if (e.getCause() != null) {
        msg = e.getCause().getMessage();
      }

      return Collections.singleton(new ValidationError(this.getValidatorName(), msg));
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected PKIXCertPathValidatorResult getValidatorResult(final List<Certificate> chain) throws GeneralSecurityException {
    X509Certificate certificate = (X509Certificate) chain.get(0);
    X509CertSelector selector = new X509CertSelector();
    selector.setCertificate(certificate);

    Set<TrustAnchor> trustAnchors = new HashSet<>();
    boolean useTrustCaCerts = this.trustCaCerts != null && !this.trustCaCerts.isEmpty();
    boolean useTrustCerts = this.trustCerts != null && !this.trustCerts.isEmpty();

    if (useTrustCaCerts) {
      for (Certificate ca : this.trustCaCerts) {
        X509Certificate x509Ca = (X509Certificate) ca;
        trustAnchors.add(new TrustAnchor(x509Ca, null));
      }
    } else {
      for (int i = 0; i < chain.size(); i++) {
        if (Certificates.isSelfSigned(chain.get(i))) {
          trustAnchors.add(new TrustAnchor((X509Certificate) chain.get(i), null));
        }
      }
    }

    PKIXBuilderParameters pkixParameters = new PKIXBuilderParameters(trustAnchors, selector);
    if (this.isRevocationEnabled()) {
      pkixParameters.setRevocationEnabled(true);
      Security.setProperty(PkixCertificateValidator.OSCP_ENABLE_PROPERTY, PkixCertificateValidator.OSCP_ENABLE_VALUE);
      CrlProvider crlProvider = this.crlProvider;
      if (crlProvider == null) {
        crlProvider = new SimpleCrlProvider();
      }

      CRL crl = Crls.toCrl(crlProvider.getCrl(certificate));
      CertStoreParameters certStoreParameters = new CollectionCertStoreParameters(Collections.singleton(crl));

      CertStore certStore = CertStore.getInstance(PkixCertificateValidator.CERTSTORE_TYPE, certStoreParameters, this.getProviderName());
      pkixParameters.addCertStore(certStore);
    } else {
      pkixParameters.setRevocationEnabled(false);
    }

    List<Certificate> list = new ArrayList<>();
    list.add(certificate);

    if (useTrustCerts) {
      list.addAll(this.trustCerts);
    } else if (chain.size() > 1) {
      for (int i = 1; i < chain.size(); i++) {
        if (!Certificates.isSelfSigned(chain.get(i))) {
          list.add(chain.get(i));
        }
      }
    }

    CertStore certStore = CertStore.getInstance(PkixCertificateValidator.CERTSTORE_TYPE, new CollectionCertStoreParameters(list), this.getProviderName());
    pkixParameters.addCertStore(certStore);

    CertPathBuilder builder = CertPathBuilder.getInstance(PkixCertificateValidator.CERTPATH_TYPE, this.getProviderName());
    PKIXCertPathBuilderResult builderResult = (PKIXCertPathBuilderResult) builder.build(pkixParameters);

    CertPathValidator validator = CertPathValidator.getInstance(PkixCertificateValidator.CERTPATH_TYPE, this.getProviderName());
    PKIXCertPathValidatorResult validatorResult = (PKIXCertPathValidatorResult) validator.validate(builderResult.getCertPath(), pkixParameters);
    return validatorResult;
  }

  protected String getValidatorName() {
    return PkixCertificateValidator.VALIDATOR_NAME;
  }

  protected String getProviderName() {
    if (Strings.isNullOrEmpty(this.provider)) {
      return ProviderType.SUN.getType();
    }
    return this.provider;
  }

}
