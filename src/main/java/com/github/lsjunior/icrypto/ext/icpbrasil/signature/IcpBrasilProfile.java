package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.SignatureProfile;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.google.common.base.Strings;

public final class IcpBrasilProfile implements SignatureProfile, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static IcpBrasilProfile instance = new IcpBrasilProfile();

  private IcpBrasilProfile() {
    super();
  }

  @Override
  public void extend(final CadesSignatureContext context) {
    SignaturePolicy policy = context.getPolicy();

    if (policy == null) {
      throw new ICryptoException("A política de assinatura digital é obrigatória");
    }

    if (Strings.isNullOrEmpty(policy.getPolicyId())) {
      throw new ICryptoException("O identificador da política de assinatura digital é obrigatória");
    }

    SignatureProfile extension = this.getSignatureProfile(context.getPolicy());
    extension.extend(context);
  }

  @Override
  public void verify(final VerificationContext context) {
    Signature signature = context.getSignature();
    SignaturePolicy policy = signature.getSignaturePolicy();

    if (policy == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.POLICY_NOT_FOUND, "A política de assinatura não foi informada", false));
      return;
    }

    if (Strings.isNullOrEmpty(policy.getPolicyId())) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.POLICY_INVALID, "A política de assinatura não foi informada", false));
      return;
    }

    SignatureProfile extension = this.getSignatureProfile(policy);
    extension.verify(context);
  }

  private SignatureProfile getSignatureProfile(final SignaturePolicy policy) {
    String policyId = policy.getPolicyId();
    if (policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RA_PREFIX)) {
      return IcpBrasilRa.getInstance();
    }
    if (policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RB_PREFIX)) {
      return IcpBrasilRb.getInstance();
    }
    if (policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RC_PREFIX)) {
      return IcpBrasilRc.getInstance();
    }
    if (policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RT_PREFIX)) {
      return IcpBrasilRt.getInstance();
    }
    if (policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RV_PREFIX)) {
      return IcpBrasilRv.getInstance();
    }
    return IcpBrasilRb.getInstance();
  }

  public static IcpBrasilProfile getInstance() {
    return IcpBrasilProfile.instance;
  }

}
