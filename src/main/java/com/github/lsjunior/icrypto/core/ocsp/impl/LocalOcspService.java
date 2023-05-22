package com.github.lsjunior.icrypto.core.ocsp.impl;

import java.util.Collection;
import java.util.Date;
import java.util.function.Function;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.type.RevokeReasonType;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.ocsp.OcspService;
import com.github.lsjunior.icrypto.core.util.BcProvider;
import com.google.common.collect.Iterables;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class LocalOcspService implements OcspService {

  private Identity issuer;

  private SignatureType signatureType;

  private Function<CertificateID, RevokeReasonType> validateFunction;

  public LocalOcspService(final Identity issuer, final SignatureType signatureType, final Function<CertificateID, RevokeReasonType> validateFunction) {
    super();
    this.issuer = issuer;
    this.signatureType = signatureType;
    this.validateFunction = validateFunction;

    if (this.validateFunction == null) {
      ICryptoLog.getLogger().error("All OCSP validation will return UNSPECIFIED");
      this.validateFunction = (certificateId) -> {
        return RevokeReasonType.UNSPECIFIED;
      };
    }
  }

  @Override
  public byte[] generate(final byte[] request) {
    try {
      OCSPReq ocspReq = new OCSPReq(request);
      Req[] reqs = ocspReq.getRequestList();
      if ((reqs == null) || (reqs.length != 1)) {
        throw new IllegalArgumentException("Invalid request size");
      }

      Req req = reqs[0];
      CertificateID certificateId = req.getCertID();

      X509CertificateHolder certificateHolder = Certificates.toCertificateHolder(this.issuer.getChain().get(0));
      X500Name name = certificateHolder.getSubject();

      ResponderID responderId = new ResponderID(name);
      RespID respId = new RespID(responderId);

      BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respId);

      Extension ocspNonce = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
      if (ocspNonce != null) {
        builder.setResponseExtensions(new Extensions(new Extension[] {ocspNonce}));
      }

      RevokeReasonType reason = this.validateFunction.apply(certificateId);
      if (reason == null) {
        builder.addResponse(certificateId, CertificateStatus.GOOD);
      } else {
        builder.addResponse(certificateId, new RevokedStatus(new Date(), reason.getCode()));
      }

      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(this.signatureType.getAlgorithm());
      contentSignerBuilder.setProvider(BcProvider.PROVIDER_NAME);
      ContentSigner contentSigner = contentSignerBuilder.build(this.issuer.getPrivateKey());

      Collection<X509CertificateHolder> chain = Certificates.toCertificateHolders(this.issuer.getChain());
      BasicOCSPResp basicResp = builder.build(contentSigner, Iterables.toArray(chain, X509CertificateHolder.class), new Date());
      OCSPResp ocspResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);

      byte[] response = ocspResp.getEncoded();
      return response;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
