package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.signature.cms.SignatureProfile;
import com.github.lsjunior.icrypto.core.signature.cms.profile.CadesA;

public class IcpBrasilRa extends AbstractIcpBrasilProfile {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static IcpBrasilRa instance = new IcpBrasilRa();

  private IcpBrasilRa() {
    super(new CadesA());
  }

  // For Extension
  IcpBrasilRa(final SignatureProfile delegate) {
    super(delegate);
  }

  @Override
  protected boolean isValidPolicyId(final String policyId) {
    return policyId.startsWith(IcpBrasilPolicies.CADES_POLICY_OID_RA_PREFIX);
  }

  public static IcpBrasilRa getInstance() {
    return IcpBrasilRa.instance;
  }

}
