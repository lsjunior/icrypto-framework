package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.CertificateExtension;
import com.github.lsjunior.icrypto.core.certificate.CertificateParameters;
import com.github.lsjunior.icrypto.core.certificate.CertificateService;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;

public class CertificateServiceImpl extends AbstractCertificateManager implements CertificateService {

  private static CertificateServiceImpl instance = new CertificateServiceImpl();

  protected CertificateServiceImpl() {
    super();
  }

  @Override
  public Identity generate(final CertificateParameters request) {
    try {
      CertificateParameters r = request;
      if (request.getExtensions() != null) {
        for (CertificateExtension extensionHandler : request.getExtensions()) {
          if (extensionHandler != null) {
            r = extensionHandler.extend(r);
          }
        }
      }

      BouncyCastleCertificateRequest bcRequest = new BouncyCastleCertificateRequest(r);
      Identity identity = this.buildCertificate(bcRequest);
      return identity;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected Identity buildCertificate(final BouncyCastleCertificateRequest request) throws OperatorCreationException, GeneralSecurityException, IOException {
    JcaX509v3CertificateBuilder builder = null;
    ContentSigner contentSigner = null;

    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(request.getSignatureAlgorithm());
    contentSignerBuilder.setProvider(request.getProvider());

    List<Certificate> chain = new ArrayList<>();
    chain.add(null);

    if ((request.getIssuerPrivateKey() != null) && (request.getIssuerCertificate() != null)) {
      builder = new JcaX509v3CertificateBuilder(request.getIssuerCertificate(), request.getSerialNumber(), request.getNotBefore(), request.getNotAfter(),
          request.getSubjectAsX500Principal(), request.getPublicKey());

      AuthorityKeyIdentifier authorityKeyIdentifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(request.getIssuerCertificate().getPublicKey());
      builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);

      if (request.isCa()) {
        SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(request.getPublicKey());
        builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
      }

      contentSigner = contentSignerBuilder.build(request.getIssuerPrivateKey());

      List<Certificate> issuerChain = request.getIssuerChain();

      chain.addAll(issuerChain);
    } else {
      builder = new JcaX509v3CertificateBuilder(request.getSubjectAsX500Name(), request.getSerialNumber(), request.getNotBefore(), request.getNotAfter(),
          request.getSubjectAsX500Name(), request.getPublicKey());

      if (request.isCa()) {
        AuthorityKeyIdentifier authorityKeyIdentifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(request.getPublicKey());
        builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
      }

      SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(request.getPublicKey());
      builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

      contentSigner = contentSignerBuilder.build(request.getPrivateKey());
    }

    List<Extension> extensions = new ArrayList<>();
    extensions.add(this.getKeyUsage(request));
    extensions.add(this.getExtendedKeyUsage(request));
    extensions.add(this.getCertificatePolicies(request));
    extensions.add(this.getOtherNames(request));
    // extensions.add(this.getComment(request));
    extensions.add(this.getCrlDistPoint(request));
    extensions.add(this.getOcspNoCheck(request));
    extensions.add(this.getOcspUrl(request));
    // extensions.add(this.getNetscapeCertType(request));
    // extensions.add(this.getNetscapeCaPolicyUrl(request));
    extensions.add(this.getPolicyUrl(request));
    extensions.add(this.getBasicConstraints(request));

    for (Extension extension : extensions) {
      if (extension != null) {
        ASN1ObjectIdentifier id = extension.getExtnId();
        boolean critical = extension.isCritical();
        ASN1Encodable value = extension.getParsedValue();
        builder.addExtension(id, critical, value);
      }
    }

    X509CertificateHolder holder = builder.build(contentSigner);

    X509Certificate certificate = (X509Certificate) Certificates.toCertificate(holder.getEncoded());

    if ((request.getIssuerPrivateKey() != null) && (request.getIssuerCertificate() != null)) {
      certificate.verify(request.getIssuerCertificate().getPublicKey());
    }

    chain.set(0, certificate);

    PrivateKey privateKey = request.getPrivateKey();
    Identity identity = new Identity(privateKey, chain);
    return identity;
  }

  public static CertificateServiceImpl getInstance() {
    return CertificateServiceImpl.instance;
  }

}
