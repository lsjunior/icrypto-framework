package com.github.lsjunior.icrypto.core.certificate.impl;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.RevokeReasonType;
import com.github.lsjunior.icrypto.core.certificate.CertificateValidator;
import com.github.lsjunior.icrypto.core.certificate.ValidationError;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.ocsp.impl.SimpleOcspProvider;

public class OcspCertificateValidator implements CertificateValidator {

  public static final String VALIDATOR_NAME = "OCSP Validator";

  private final OcspProvider ocspProvider;

  private final boolean ignoreTryLater;

  public OcspCertificateValidator() {
    this(new SimpleOcspProvider());
  }

  public OcspCertificateValidator(final OcspProvider ocspProvider) {
    this(ocspProvider, false);
  }

  public OcspCertificateValidator(final OcspProvider ocspProvider, final boolean ignoreTryLater) {
    super();
    this.ocspProvider = ocspProvider;
    this.ignoreTryLater = ignoreTryLater;
  }

  @Override
  public Collection<ValidationError> validate(final List<Certificate> chain) {
    try {
      Certificate certificate = chain.get(0);
      Certificate issuer = null;

      if (Certificates.isSelfSigned(certificate)) {
        issuer = certificate;
      } else {
        if (chain.size() < 2) {
          return Collections.singleton(
              new ValidationError(OcspCertificateValidator.VALIDATOR_NAME, "Certificate chain must be greater than 1(certificate and issuer certificate"));
        }
        issuer = chain.get(1);
      }

      byte[] resp = this.ocspProvider.getOcsp(certificate, issuer);
      OCSPResp ocspResp = new OCSPResp(resp);
      int status = ocspResp.getStatus();
      if (ocspResp.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
        if (!((ocspResp.getStatus() == OCSPResponseStatus.TRY_LATER) && (this.ignoreTryLater))) {
          return Collections.singleton(new ValidationError(OcspCertificateValidator.VALIDATOR_NAME, "Invalid response status " + status));
        }
      }

      Object responseObject = ocspResp.getResponseObject();

      if (responseObject instanceof BasicOCSPResp) {
        BasicOCSPResp basicOcspResp = (BasicOCSPResp) responseObject;
        SingleResp[] singleResps = basicOcspResp.getResponses();
        List<ValidationError> errors = new ArrayList<>();
        for (SingleResp singleResp : singleResps) {
          CertificateStatus certificateStatus = singleResp.getCertStatus();
          if (certificateStatus != null) {
            RevokeReasonType revokeReason = null;
            if (certificateStatus instanceof RevokedStatus) {
              RevokedStatus revokedStatus = (RevokedStatus) certificateStatus;
              revokeReason = RevokeReasonType.get(revokedStatus.getRevocationReason());
            }

            if (revokeReason != null) {
              errors.add(new ValidationError(OcspCertificateValidator.VALIDATOR_NAME, "Certificate revoked(" + revokeReason.name() + ")"));
            } else {
              errors.add(new ValidationError(OcspCertificateValidator.VALIDATOR_NAME, "Certificate revoked(Unknow)"));
            }
          }
        }

        return errors;
      }

      return Collections.emptyList();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
