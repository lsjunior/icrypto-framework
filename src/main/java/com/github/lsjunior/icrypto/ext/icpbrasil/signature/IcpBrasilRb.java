package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.signature.cms.profile.CadesEpes;

public final class IcpBrasilRb extends AbstractIcpBrasilProfile {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static IcpBrasilRb instance = new IcpBrasilRb();

  private IcpBrasilRb() {
    super(new CadesEpes());
  }

  @Override
  protected boolean isValidPolicyId(final String policyId) {
    return policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RB_PREFIX);
  }

  public static IcpBrasilRb getInstance() {
    return IcpBrasilRb.instance;
  }

}
