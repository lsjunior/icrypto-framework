package com.github.lsjunior.icrypto.core.signature.cms;

import java.util.Collection;

import com.github.lsjunior.icrypto.api.model.SignaturePolicy;

public interface SignaturePolicyProvider {

  Collection<String> getPolicies();

  SignaturePolicy getPolicy(String policyId);

}
