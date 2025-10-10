package com.github.lsjunior.icrypto.core.signature.cms;

import java.util.Collection;

import com.github.lsjunior.icrypto.api.asn1.Lpa;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;

public interface SignaturePolicyProvider {

  Lpa getLpa();

  Collection<String> getPolicies();

  SignaturePolicy getPolicy(String policyId);

}
