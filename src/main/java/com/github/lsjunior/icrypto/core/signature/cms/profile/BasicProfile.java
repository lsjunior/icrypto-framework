package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.io.Serializable;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.util.Crls;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.SignatureProfile;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.google.common.base.Strings;

public class BasicProfile implements SignatureProfile, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public BasicProfile() {
    super();
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  @Override
  public void extend(final CadesSignatureContext context) {
    try {
      ICryptoLog.getLogger().info("Extending...");

      CMSSignedData signedData = new CMSSignedData(Files.newInputStream(context.getSignedData().toPath()));
      List<Certificate> chain = context.getChain();
      Store certificateStore = signedData.getCertificates();
      Store crlStore = signedData.getCRLs();
      Store attributeStore = signedData.getAttributeCertificates();
      // CrlProvider provider = context.getCrlProvider();

      Certificate certificate = chain.get(0);
      Collection<X509CertificateHolder> certificateHolders = certificateStore.getMatches(null);
      Collection<Certificate> certificates = Certificates.toCertificates(certificateHolders);
      if (!certificates.contains(certificate)) {
        certificates.add(certificate);
      }
      certificateStore = Certificates.toStore(certificates);

      // Collection<X509CRLHolder> crlHolders = crlStore.getMatches(null);
      // Collection<CRL> crls = Crls.toCrls(crlHolders);
      // crls.addAll(CadesServiceHelper.getCrls(certificate, provider));
      // crlStore = Crls.toStore(crls);
      crlStore = Crls.toStore(Collections.emptyList());

      signedData = CMSSignedData.replaceCertificatesAndCRLs(signedData, certificateStore, attributeStore, crlStore);

      Files.write(context.getSignedData().toPath(), signedData.getEncoded());
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public void verify(final VerificationContext context) {
    Signature signature = context.getSignature();
    List<Certificate> chain = signature.getChain();

    if ((chain == null) || (chain.isEmpty())) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_NOT_FOUND, "Certificate not found", true));
    } else {
      X509Certificate certificate = (X509Certificate) signature.getChain().get(0);
      Date signingTime = signature.getSigningTime();
      Date notBefore = certificate.getNotBefore();
      Date notAfter = certificate.getNotAfter();
      if (signingTime != null) {
        if ((notBefore.after(signingTime)) || (notAfter.before(signingTime))) {
          signature.getErrors().add(new ErrorMessage(CadesErrors.SIGNING_TIME_INVALID, "Invalid signing time", true));
        }
      } else {
        signature.getErrors().add(new ErrorMessage(CadesErrors.SIGNING_TIME_INVALID, "Signing time not found", false));
      }
    }

    String contentType = signature.getContentType();
    if (Strings.isNullOrEmpty(contentType)) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.CONTENT_TYPE_NOT_FOUND, "ContentType not found", true));
    }
  }

}
