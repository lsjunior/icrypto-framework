package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.nio.file.Files;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesServiceHelper;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.google.common.base.Strings;

public class CadesEpes extends CadesBes {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public CadesEpes() {
    super();
  }

  @Override
  public void extend(final CadesSignatureContext context) {
    super.extend(context);

    SignaturePolicy policy = context.getPolicy();

    if (policy == null) {
      throw new ICryptoException("Policy is mandatory");
    }

    if (Strings.isNullOrEmpty(policy.getPolicyId())) {
      throw new ICryptoException("Policy ID is mandatory");
    }

    if (policy.getDigestType() == null) {
      throw new ICryptoException("Policy hash type is mandatory");
    }

    if (policy.getDigestValue() == null) {
      throw new ICryptoException("Policy hash value is mandatory");
    }

    if ((context.getValidatePolicy() != null) && (context.getValidatePolicy().booleanValue())) {
      try {
        if ((policy.getRequiredSignedAttributes() != null) || (policy.getRequiredSignedAttributes() != null)) {
          CMSSignedData signedData = new CMSSignedData(Files.newInputStream(context.getSignedData().toPath()));
          SignerInformationStore signerInformationStore = signedData.getSignerInfos();
          for (Object o : signerInformationStore.getSigners()) {
            SignerInformation signerInformation = (SignerInformation) o;
            SignerInfo signerInfo = signerInformation.toASN1Structure();

            String sid = CadesServiceHelper.getSID(signerInfo);
            if (sid.equals(context.getSignerId())) {
              if (policy.getRequiredSignedAttributes() != null) {
                AttributeTable table = signerInformation.getSignedAttributes();
                for (String id : policy.getRequiredSignedAttributes()) {
                  if (table.get(new ASN1ObjectIdentifier(id)) == null) {
                    throw new ICryptoException("Required signed attribute '" + id + "' nod found");
                  }
                }
              }
              if (policy.getRequiredUnsignedAttributes() != null) {
                AttributeTable table = signerInformation.getUnsignedAttributes();
                for (String id : policy.getRequiredUnsignedAttributes()) {
                  if (table.get(new ASN1ObjectIdentifier(id)) == null) {
                    throw new ICryptoException("Required unsigned attribute '" + id + "' nod found");
                  }
                }
              }
            }
          }
        }
      } catch (Exception e) {
        throw new ICryptoException(e);
      }
    }
  }

  @Override
  public void doVerify(final VerificationContext context, final Signature signature) throws Exception {
    super.doVerify(context, signature);
    SignaturePolicy policy = signature.getSignaturePolicy();

    if (policy == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.POLICY_NOT_FOUND, "Policy not found", false));
      return;
    }

    if (Strings.isNullOrEmpty(policy.getPolicyId())) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.POLICY_INVALID, "Policy ID is empty", false));
    }

    if (policy.getDigestType() == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.POLICY_ALGORITHM_INVALID, "Policy hash type is empty", false));
    }

    if (policy.getDigestValue() == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.POLICY_HASH_INVALID, "Policy hash value is empty", false));
    }
  }

}
