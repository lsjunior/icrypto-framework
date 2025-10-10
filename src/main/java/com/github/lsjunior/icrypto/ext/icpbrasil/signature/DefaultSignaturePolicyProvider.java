package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import java.io.IOException;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import com.github.lsjunior.icrypto.api.asn1.Lpa;
import com.github.lsjunior.icrypto.api.asn1.PolicyInfo;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.api.model.SignatureVersion;
import com.github.lsjunior.icrypto.core.signature.cms.SignaturePolicyHelper;
import com.github.lsjunior.icrypto.core.signature.cms.SignaturePolicyProvider;
import com.google.common.base.Preconditions;
import com.google.common.io.Resources;

public class DefaultSignaturePolicyProvider implements SignaturePolicyProvider {

  private final URL url;

  private Lpa lpa;

  private Map<String, SignaturePolicy> map;

  public DefaultSignaturePolicyProvider(final URL url) throws IOException {
    super();
    Preconditions.checkArgument(url != null);
    this.url = url;
    this.read(Resources.toByteArray(url));
  }

  protected void read(final byte[] bytes) throws IOException {
    this.lpa = Lpa.getInstance(bytes);
    this.map = new HashMap<>();

    for (int i = 0; i < this.lpa.getPolicyInfos().size(); i++) {
      PolicyInfo policyInfo = this.lpa.getPolicyInfos().getPolicyAt(i);
      SignaturePolicy signaturePolicy = this.getSignaturePolicy(policyInfo);
      this.map.put(policyInfo.getPolicyId().getId(), signaturePolicy);
    }
  }

  @Override
  public Lpa getLpa() {
    return this.lpa;
  }

  @Override
  public Collection<String> getPolicies() {
    if (this.map == null) {
      throw new IllegalStateException("Lista de política de assinatura não lida");
    }
    return this.map.keySet();
  }

  @Override
  public SignaturePolicy getPolicy(final String policyId) {
    if (this.map == null) {
      throw new IllegalStateException("Lista de política de assinatura não lida");
    }
    return this.map.get(policyId);
  }

  protected SignaturePolicy getSignaturePolicy(final PolicyInfo policyInfo) throws IOException {
    if (policyInfo.getPolicyURI() != null) {
      URL url = new URL(policyInfo.getPolicyURI().getString());
      byte[] bytes = Resources.toByteArray(url);
      com.github.lsjunior.icrypto.api.asn1.SignaturePolicy signaturePolicy = com.github.lsjunior.icrypto.api.asn1.SignaturePolicy.getInstance(bytes);
      SignaturePolicy sp = SignaturePolicyHelper.toSignaturePolicy(signaturePolicy);

      // FIXME Erro ao gravar e restaurar
      sp.setEncoded(bytes);
      sp.setPolicyName(url.getFile().substring(1));
      sp.setPolicyUrl(url.toString());
      sp.setSignatureVersion(this.getVersion(policyInfo.getPolicyId().getId()));
      sp.setValid(policyInfo.isValid());
      return sp;
    }
    return null;
  }

  protected SignatureVersion getVersion(final String policyId) {
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V1_PATTERN, policyId)) {
      return SignatureVersion.V1;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V11_PATTERN, policyId)) {
      return SignatureVersion.V1;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V12_PATTERN, policyId)) {
      return SignatureVersion.V1;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V2_PATTERN, policyId)) {
      return SignatureVersion.V1;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V21_PATTERN, policyId)) {
      return SignatureVersion.V2;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V22_PATTERN, policyId)) {
      return SignatureVersion.V2;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V23_PATTERN, policyId)) {
      return SignatureVersion.V3;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V24_PATTERN, policyId)) {
      return SignatureVersion.V4;
    }
    if (Pattern.matches(IcpBrasilPolicies.CADES_POLICY_OID_V25_PATTERN, policyId)) {
      return SignatureVersion.V5;
    }

    if (Pattern.matches(IcpBrasilPolicies.PADES_POLICY_OID_V1_PATTERN, policyId)) {
      return SignatureVersion.V1;
    }
    if (Pattern.matches(IcpBrasilPolicies.PADES_POLICY_OID_V11_PATTERN, policyId)) {
      return SignatureVersion.V1;
    }
    if (Pattern.matches(IcpBrasilPolicies.PADES_POLICY_OID_V12_PATTERN, policyId)) {
      return SignatureVersion.V2;
    }
    if (Pattern.matches(IcpBrasilPolicies.PADES_POLICY_OID_V13_PATTERN, policyId)) {
      return SignatureVersion.V3;
    }
    if (Pattern.matches(IcpBrasilPolicies.PADES_POLICY_OID_V14_PATTERN, policyId)) {
      return SignatureVersion.V4;
    }

    return null;
  }

}
