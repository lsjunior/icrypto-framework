package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.SignatureProfile;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.CertificadoIcp;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.TipoFormato;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.TipoPessoa;
import com.google.common.base.Strings;

public abstract class AbstractIcpBrasilProfile implements SignatureProfile, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private SignatureProfile delegate;

  AbstractIcpBrasilProfile(final SignatureProfile delegate) {
    super();
    this.delegate = delegate;
  }

  @Override
  public void extend(final CadesSignatureContext context) {
    this.delegate.extend(context);

    SignaturePolicy policy = context.getPolicy();
    if ((policy == null) || (Strings.isNullOrEmpty(policy.getPolicyId()))) {
      throw new ICryptoException("Política de assinatura deve ser informada");
    }

    String policyId = policy.getPolicyId();
    if (!this.isValidPolicyId(policyId)) {
      throw new ICryptoException("Identificador da política de assinatura inválido " + policyId);
    }

    List<Certificate> chain = context.getChain();
    Certificate certificate = chain.get(0);
    if (!this.isValidCertificate(certificate)) {
      throw new ICryptoException("Certificado inválido, não está de acordo com os padrões do ICP-Brasil");
    }
  }

  @Override
  public void verify(final VerificationContext context) {
    this.delegate.verify(context);
    Signature signature = context.getSignature();
    List<Certificate> chain = signature.getChain();
    if ((chain != null) && (!chain.isEmpty())) {
      Certificate certificate = chain.get(0);
      if (!this.isValidCertificate(certificate)) {
        String msg = "Certificado inválido, não está de acordo com os padrões do ICP-Brasil";
        signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_INVALID, msg, false));
      }
    }
  }

  protected boolean isValidCertificate(final Certificate certificate) {
    CertificadoIcp certificadoIcp = CertificadoIcp.getInstance(certificate);
    if (certificadoIcp.getTipoPessoa() == TipoPessoa.DESCONHECIDO) {
      return false;
    }
    if (certificadoIcp.getTipoFormato() == TipoFormato.DESCONHECIDO) {
      return false;
    }
    // TODO validar a hierarquia do certificado
    return true;
  }

  protected abstract boolean isValidPolicyId(final String policyId);

}
