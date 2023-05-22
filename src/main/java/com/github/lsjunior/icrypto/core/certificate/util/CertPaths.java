package com.github.lsjunior.icrypto.core.certificate.util;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.github.lsjunior.icrypto.api.type.CertPathEncodingType;
import com.github.lsjunior.icrypto.api.type.CertificateType;

public abstract class CertPaths {

  private static final String CERTPATH_TYPE = "PKIX";

  private static final String CERTSTORE_TYPE = "Collection";

  private CertPaths() {
    //
  }

  public static byte[] toByteArray(final Collection<Certificate> certificates) throws GeneralSecurityException {
    CertificateFactory certFactory = CertificateFactory.getInstance(CertificateType.X509.getType());
    List<Certificate> newList = new LinkedList<>();
    for (Certificate certificate : certificates) {
      if (!newList.contains(certificate)) {
        newList.add(certificate);
      }
    }
    CertPath certPath = certFactory.generateCertPath(newList);
    byte[] encoded = certPath.getEncoded(CertPathEncodingType.PKIPATH.getType());
    return encoded;
  }

  public static List<Certificate> toCertificate(final CertPath certPath) {
    if (certPath == null) {
      return null;
    }

    List<Certificate> certs = new ArrayList<>();
    for (Certificate c : certPath.getCertificates()) {
      certs.add(c);
    }
    return certs;
  }

  public static CertPath toCertPath(final byte[] bytes) throws GeneralSecurityException {
    CertificateFactory certFactory = CertificateFactory.getInstance(CertificateType.X509.getType());
    CertPath certPath = certFactory.generateCertPath(new ByteArrayInputStream(bytes), CertPathEncodingType.PKIPATH.getType());
    return certPath;
  }

  public static CertPath toCertPath(final Certificate certificate, final Collection<Certificate> certificates) throws GeneralSecurityException {
    X509CertSelector selector = new X509CertSelector();
    selector.setCertificate((X509Certificate) certificate);

    Set<TrustAnchor> trustAnchors = new HashSet<>();

    for (Certificate c : certificates) {
      if (Certificates.isSelfSigned(c)) {
        trustAnchors.add(new TrustAnchor((X509Certificate) c, null));
      }
    }

    PKIXBuilderParameters pkixParameters = new PKIXBuilderParameters(trustAnchors, selector);
    pkixParameters.setMaxPathLength(-1);
    pkixParameters.setRevocationEnabled(false);

    List<Certificate> list = new ArrayList<>();

    for (Certificate c : certificates) {
      if (!Certificates.isSelfSigned(c)) {
        list.add(c);
      }
    }

    if ((list != null) && (!list.isEmpty())) {
      CertStore intermediateCertStore = CertStore.getInstance(CertPaths.CERTSTORE_TYPE, new CollectionCertStoreParameters(list));
      pkixParameters.addCertStore(intermediateCertStore);
    }

    CertPathBuilder builder = CertPathBuilder.getInstance(CertPaths.CERTPATH_TYPE);
    PKIXCertPathBuilderResult builderResult = (PKIXCertPathBuilderResult) builder.build(pkixParameters);
    CertPath certPath = builderResult.getCertPath();
    List<Certificate> realChain = new ArrayList<>();
    realChain.addAll(certPath.getCertificates());

    TrustAnchor trustAnchor = builderResult.getTrustAnchor();
    if (trustAnchor != null) {
      Certificate root = trustAnchor.getTrustedCert();
      realChain.add(root);
    }

    CertificateFactory certFactory = CertificateFactory.getInstance(CertificateType.X509.getType());
    certPath = certFactory.generateCertPath(realChain);
    return certPath;
  }
}
