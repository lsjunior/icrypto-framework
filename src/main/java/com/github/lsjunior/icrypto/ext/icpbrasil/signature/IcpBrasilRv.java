package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.signature.cms.profile.CadesX;

public final class IcpBrasilRv extends AbstractIcpBrasilProfile {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static IcpBrasilRv instance = new IcpBrasilRv();

  private IcpBrasilRv() {
    super(new CadesX());
  }

  @Override
  protected boolean isValidPolicyId(final String policyId) {
    return policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RV_PREFIX);
  }

  public static IcpBrasilRv getInstance() {
    return IcpBrasilRv.instance;
  }

}
