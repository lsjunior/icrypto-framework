package com.github.lsjunior.icrypto.core.signature.cms;

import com.github.lsjunior.icrypto.api.model.SignaturePolicy;

public interface SignatureProfileProvider {

  SignatureProfile getExtensionByPolicy(SignaturePolicy policy);

  SignatureProfile getExtensionByType(Object type);

}
