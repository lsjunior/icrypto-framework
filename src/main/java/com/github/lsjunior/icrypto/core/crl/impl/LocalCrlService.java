package com.github.lsjunior.icrypto.core.crl.impl;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.CrlEntry;
import com.github.lsjunior.icrypto.core.crl.CrlParameters;
import com.github.lsjunior.icrypto.core.crl.CrlService;
import com.github.lsjunior.icrypto.core.util.BcProvider;

public class LocalCrlService implements CrlService {

  private final Identity issuer;

  private final SignatureType signType;

  public LocalCrlService(final Identity issuer, final SignatureType signType) {
    super();
    this.issuer = issuer;
    this.signType = signType;
  }

  @Override
  public byte[] generate(final CrlParameters parameters) {
    try {
      X509Certificate certificate = (X509Certificate) this.issuer.getChain().get(0);
      Date thisUpdate = parameters.getThisUpdate();
      if (thisUpdate == null) {
        thisUpdate = new Date();
      }
      X509v2CRLBuilder builder = new X509v2CRLBuilder(Certificates.toX500Name(certificate.getSubjectX500Principal()), thisUpdate);
      if (parameters.getNextUpdate() != null) {
        builder.setNextUpdate(parameters.getNextUpdate());
      } else {
        LocalDateTime localDateTime = LocalDateTime.now().plusHours(12);
        Date nextUpdate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        builder.setNextUpdate(nextUpdate);
      }

      AuthorityKeyIdentifier authorityKeyIdentifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(certificate);
      builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);

      builder.addExtension(Extension.cRLNumber, false, new CRLNumber(parameters.getNumber()));

      if (parameters.getOldCrl() != null) {
        X509CRLHolder current = new X509CRLHolder(parameters.getOldCrl());
        builder.addCRL(current);
      }

      PrivateKey privateKey = this.issuer.getPrivateKey();
      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(this.signType.getAlgorithm());
      contentSignerBuilder.setProvider(BcProvider.PROVIDER_NAME);
      ContentSigner contentSigner = contentSignerBuilder.build(privateKey);

      for (CrlEntry entry : parameters.getEntries()) {
        builder.addCRLEntry(entry.getSerialNumber(), entry.getDate(), entry.getReason().getCode());
      }

      X509CRLHolder crl = builder.build(contentSigner);
      return crl.getEncoded();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
