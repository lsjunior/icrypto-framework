package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.certificate.CertificateReader;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;

public class Pkcs7CertificateReader implements CertificateReader, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public Pkcs7CertificateReader() {
    super();
  }

  @Override
  public List<Certificate> read(final InputStream inputStream) {
    try {
      CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
      Collection<X509CertificateHolder> certificates = cmsSignedData.getCertificates().getMatches(null);
      List<Certificate> list = new LinkedList<>();
      if (certificates.size() > 0) {
        X509CertificateHolder principal = certificates.iterator().next();
        Certificate principalCertificate = Certificates.toCertificate(principal);

        list.add(principalCertificate);

        X509CertificateHolder issuer = this.getIssuer(principal.getIssuer(), certificates);
        while (issuer != null) {
          Certificate issuerCertificate = Certificates.toCertificate(issuer);
          list.add(issuerCertificate);

          if (issuer.getIssuer().equals(issuer.getSubject())) {
            break;
          }

          issuer = this.getIssuer(issuer.getIssuer(), certificates);
        }
      }
      return list;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public List<Certificate> readAll(final InputStream inputStream) {
    try {
      CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
      Collection<X509CertificateHolder> certificates = cmsSignedData.getCertificates().getMatches(null);
      List<Certificate> list = new LinkedList<>();
      for (X509CertificateHolder holder : certificates) {
        list.add(Certificates.toCertificate(holder));
      }
      return list;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  private X509CertificateHolder getIssuer(final X500Name name, final Collection<X509CertificateHolder> certificates) {
    for (X509CertificateHolder holder : certificates) {
      if (holder.getSubject().equals(name)) {
        return holder;
      }
    }
    return null;
  }

}
