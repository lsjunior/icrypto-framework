package com.github.lsjunior.icrypto.core.signature.cms;

import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.asn1.AlgAndLength;
import com.github.lsjunior.icrypto.api.asn1.AlgorithmConstraintSet;
import com.github.lsjunior.icrypto.api.asn1.AlgorithmConstraints;
import com.github.lsjunior.icrypto.api.asn1.CmsAttrs;
import com.github.lsjunior.icrypto.api.asn1.CommonRules;
import com.github.lsjunior.icrypto.api.asn1.SignPolicyInfo;
import com.github.lsjunior.icrypto.api.asn1.SignaturePolicy;
import com.github.lsjunior.icrypto.api.asn1.SignerAndVerifierRules;
import com.github.lsjunior.icrypto.api.asn1.SignerRules;
import com.github.lsjunior.icrypto.api.model.SignatureConstraint;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public abstract class SignaturePolicyHelper {

  private SignaturePolicyHelper() {
    //
  }

  public static com.github.lsjunior.icrypto.api.model.SignaturePolicy toSignaturePolicy(final SignaturePolicy signaturePolicy) {
    if (signaturePolicy == null) {
      return null;
    }
    try {
      SignPolicyInfo signPolicyInfo = signaturePolicy.getSignPolicyInfo();

      com.github.lsjunior.icrypto.api.model.SignaturePolicy p = new com.github.lsjunior.icrypto.api.model.SignaturePolicy();
      p.setDetached(SignaturePolicyHelper.getDetached(signPolicyInfo));
      p.setDigestType(Asn1Objects.getDigestType(signaturePolicy.getSignPolicyHashAlg()));
      p.setEncoded(signaturePolicy.getEncoded());
      p.setDigestValue(signaturePolicy.getSignPolicyHash().getValue().getOctets());
      p.setNotAfter(SignaturePolicyHelper.getNotAfter(signPolicyInfo));
      p.setNotBefore(SignaturePolicyHelper.getNotBefore(signPolicyInfo));
      p.setPolicyId(SignaturePolicyHelper.getPolicyId(signPolicyInfo));
      p.setRequiredSignedAttributes(SignaturePolicyHelper.getRequiredSignedAttributes(signPolicyInfo));
      p.setRequiredUnsignedAttributes(SignaturePolicyHelper.getRequiredUnsignedAttributes(signPolicyInfo));
      p.setSignatureConstraints(SignaturePolicyHelper.getSignatureConstraints(signPolicyInfo));
      return p;
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  private static boolean getDetached(final SignPolicyInfo signPolicyInfo) {
    CommonRules commonRules = signPolicyInfo.getSignatureValidationPolicy().getCommonRules();
    if (commonRules != null) {
      SignerAndVerifierRules signerAndVerifierRules = commonRules.getSignerAndVerifierRules();
      if (signerAndVerifierRules != null) {
        SignerRules signerRules = signerAndVerifierRules.getSignerRules();
        if (signerRules != null) {
          ASN1Boolean asn1Boolean = signerRules.getExternalSignedData();
          if ((asn1Boolean != null) && (!asn1Boolean.isTrue())) {
            return false;
          }
        }
      }
    }
    return true;
  }

  private static Date getNotAfter(final SignPolicyInfo signPolicyInfo) throws ParseException {
    return signPolicyInfo.getSignatureValidationPolicy().getSigningPeriod().getNotAfter().getDate();
  }

  private static Date getNotBefore(final SignPolicyInfo signPolicyInfo) throws ParseException {
    return signPolicyInfo.getSignatureValidationPolicy().getSigningPeriod().getNotBefore().getDate();
  }

  private static String getPolicyId(final SignPolicyInfo signPolicyInfo) {
    return signPolicyInfo.getSignPolicyIdentifier().getIdentifier().getId();
  }

  private static Set<SignatureConstraint> getSignatureConstraints(final SignPolicyInfo signPolicyInfo) {
    Set<SignatureConstraint> set = new HashSet<>();
    CommonRules commonRules = signPolicyInfo.getSignatureValidationPolicy().getCommonRules();
    if (commonRules != null) {
      AlgorithmConstraintSet algorithmConstraintSet = commonRules.getAlgorithmConstraintSet();
      if (algorithmConstraintSet != null) {
        AlgorithmConstraints algorithmConstraints = algorithmConstraintSet.getSignerAlgorithmConstraints();
        if (algorithmConstraints != null) {
          SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
          for (int i = 0; i < algorithmConstraints.size(); i++) {
            AlgAndLength algAndLength = algorithmConstraints.getObjectAt(i);
            int minKeySize = algAndLength.getMinKeyLength().getValue().intValue();

            SignatureType signatureType = null;
            for (SignatureType st : SignatureType.values()) {
              AlgorithmIdentifier algorithmIdentifier = signatureAlgorithmIdentifierFinder.find(st.getAlgorithm());
              if (algAndLength.getAlgID().equals(algorithmIdentifier.getAlgorithm())) {
                signatureType = st;
                break;
              }
            }

            SignatureConstraint cmsSignatureType = new SignatureConstraint(signatureType, minKeySize);
            set.add(cmsSignatureType);
          }
        }
      }
    }
    return Collections.unmodifiableSet(set);
  }

  private static Set<String> getRequiredSignedAttributes(final SignPolicyInfo signPolicyInfo) {
    Set<String> set = new HashSet<>();
    SignerAndVerifierRules signerAndVerifierRules = signPolicyInfo.getSignatureValidationPolicy().getCommonRules().getSignerAndVerifierRules();
    if (signerAndVerifierRules != null) {
      SignerRules signerRules = signerAndVerifierRules.getSignerRules();
      CmsAttrs cmsAttrs = signerRules.getMandatedSignedAttr();
      if (cmsAttrs != null) {
        for (int i = 0; i < cmsAttrs.size(); i++) {
          set.add(cmsAttrs.getObjectAt(i).getId());
        }
      }
    }
    return set;
  }

  private static Set<String> getRequiredUnsignedAttributes(final SignPolicyInfo signPolicyInfo) {
    Set<String> set = new HashSet<>();
    SignerAndVerifierRules signerAndVerifierRules = signPolicyInfo.getSignatureValidationPolicy().getCommonRules().getSignerAndVerifierRules();
    if (signerAndVerifierRules != null) {
      SignerRules signerRules = signerAndVerifierRules.getSignerRules();
      CmsAttrs cmsAttrs = signerRules.getMandatedUnsignedAttr();
      if (cmsAttrs != null) {
        for (int i = 0; i < cmsAttrs.size(); i++) {
          set.add(cmsAttrs.getObjectAt(i).getId());
        }
      }
    }
    return set;
  }

}
