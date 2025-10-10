package com.github.lsjunior.icrypto.test.cert;

import java.net.URI;
import java.net.URL;

import org.junit.jupiter.api.Test;

import com.github.lsjunior.icrypto.api.asn1.PolicyInfo;
import com.github.lsjunior.icrypto.ext.icpbrasil.signature.DefaultSignaturePolicyProvider;

public class DefaultSignaturePolicyProviderTest {

  @Test
  void testCades() throws Exception {
    URL url = new URI("http://politicas.icpbrasil.gov.br/LPA_CAdES.der").toURL();
    DefaultSignaturePolicyProvider provider = new DefaultSignaturePolicyProvider(url);
    System.out.println(provider.getLpa().getVersion());
    for (int i = 0; i < provider.getLpa().getPolicyInfos().size(); i++) {
      PolicyInfo policyInfo = provider.getLpa().getPolicyInfos().getPolicyAt(i);
      System.out.println(policyInfo.getPolicyId());
      System.out.println("  " + provider.getPolicy(policyInfo.getPolicyId().getId()).getPolicyName());
      System.out.println("  " + provider.getPolicy(policyInfo.getPolicyId().getId()).getSignatureVersion());
      System.out.println("  " + policyInfo.getPolicyURI());
    }
  }

  @Test
  void testPades() throws Exception {
    URL url = new URI("http://politicas.icpbrasil.gov.br/LPA_PAdES.der").toURL();
    DefaultSignaturePolicyProvider provider = new DefaultSignaturePolicyProvider(url);
    System.out.println(provider.getLpa().getVersion());
    for (int i = 0; i < provider.getLpa().getPolicyInfos().size(); i++) {
      PolicyInfo policyInfo = provider.getLpa().getPolicyInfos().getPolicyAt(i);
      System.out.println(policyInfo.getPolicyId());
      System.out.println("  " + provider.getPolicy(policyInfo.getPolicyId().getId()).getPolicyName());
      System.out.println("  " + provider.getPolicy(policyInfo.getPolicyId().getId()).getSignatureVersion());
      System.out.println("  " + policyInfo.getPolicyURI());
    }
  }

}
