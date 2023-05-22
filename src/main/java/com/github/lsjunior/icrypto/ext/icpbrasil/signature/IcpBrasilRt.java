package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.signature.cms.profile.CadesT;

public final class IcpBrasilRt extends AbstractIcpBrasilProfile {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static IcpBrasilRt instance = new IcpBrasilRt();

  private IcpBrasilRt() {
    super(new CadesT());
  }

  @Override
  protected boolean isValidPolicyId(final String policyId) {
    return policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RT_PREFIX);
  }

  public static IcpBrasilRt getInstance() {
    return IcpBrasilRt.instance;
  }

}
