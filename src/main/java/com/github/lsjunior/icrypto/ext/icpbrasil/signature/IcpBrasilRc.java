package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.signature.cms.profile.CadesXl;

public final class IcpBrasilRc extends AbstractIcpBrasilProfile {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static IcpBrasilRc instance = new IcpBrasilRc();

  private IcpBrasilRc() {
    super(new CadesXl());
  }

  @Override
  protected boolean isValidPolicyId(final String policyId) {
    return policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RC_PREFIX);
  }

  public static IcpBrasilRc getInstance() {
    return IcpBrasilRc.instance;
  }

}
