package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesServiceHelper;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;

public class CadesBes extends BasicProfile {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public CadesBes() {
    super();
  }

  @Override
  @SuppressWarnings({"rawtypes", "unchecked"})
  public void extend(final CadesSignatureContext context) {
    super.extend(context);

    try {
      CMSSignedData signedData = new CMSSignedData(Files.newInputStream(context.getSignedData().toPath()));
      SignerInformationStore signerInformationStore = signedData.getSignerInfos();
      List list = new ArrayList();
      for (Object o : signerInformationStore.getSigners()) {
        SignerInformation signerInformation = (SignerInformation) o;

        SignerInfo signerInfo = signerInformation.toASN1Structure();

        String sid = CadesServiceHelper.getSID(signerInfo);
        if (sid.equals(context.getSignerId())) {
          list.add(this.updateSignerInformation(context, signedData, signerInformation));
        } else {
          list.add(signerInformation);
        }
      }

      SignerInformationStore tmpSignerInformationStore = new SignerInformationStore(list);

      signedData = CMSSignedData.replaceSigners(signedData, tmpSignerInformationStore);

      Files.write(context.getSignedData().toPath(), signedData.getEncoded());
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public void verify(final VerificationContext context) {
    super.verify(context);

    Signature signature = context.getSignature();
    try {
      this.doVerify(context, signature);
    } catch (Exception e) {
      ICryptoLog.getLogger().warn(e.getMessage(), e);
      signature.getErrors().add(new ErrorMessage(CadesErrors.UNCAUGHT_ERROR, "Uncaught error: " + e.getMessage(), true));
    }
  }

  protected SignerInformation updateSignerInformation(final CadesSignatureContext context, final CMSSignedData cmsSignedData,
      final SignerInformation currentSignerInformation) throws Exception {
    ICryptoLog.getLogger().debug("Updating " + context.getSignerId() + " for " + cmsSignedData);
    return currentSignerInformation;
  }

  protected void doVerify(final VerificationContext context, final Signature signature) throws Exception {
    // Do nothing...
    ICryptoLog.getLogger().debug("Context: " + context);
    ICryptoLog.getLogger().debug("Signature: " + signature);
  }

}
