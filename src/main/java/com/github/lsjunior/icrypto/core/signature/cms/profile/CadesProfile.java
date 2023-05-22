package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.Document;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.model.SignaturePolicy;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.SignatureProfile;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;

public final class CadesProfile implements SignatureProfile, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static CadesProfile instance = new CadesProfile();

  private final SignatureProfile cadesBes = new CadesBes();

  private final SignatureProfile cadesEpes = new CadesEpes();

  private final SignatureProfile cadesT = new CadesT();

  private final SignatureProfile cadesC = new CadesC();

  private final SignatureProfile cadesX = new CadesX();

  private final SignatureProfile cadesXl = new CadesXl();

  private final SignatureProfile cadesA = new CadesA();

  private CadesProfile() {
    super();
  }

  @Override
  public void extend(final CadesSignatureContext context) {
    SignaturePolicy policy = context.getPolicy();

    SignatureProfile extension = this.getCadesType(policy);

    extension.extend(context);
  }

  @Override
  public void verify(final VerificationContext context) {
    Document document = context.getDocument();
    for (Signature signature : document.getSignatures()) {
      Set<String> signed = signature.getSignedAttributes().keySet();
      Set<String> unsigned = signature.getUnsignedAttributes().keySet();

      SignatureProfile extension = this.getCadesType(signed, unsigned);
      extension.verify(context);
    }
  }

  private SignatureProfile getCadesType(final SignaturePolicy policy) {
    if (policy == null) {
      Set<String> empty = Collections.emptySet();
      return this.getCadesType(empty, empty);
    }

    Set<String> signed = policy.getRequiredSignedAttributes();
    Set<String> unsigned = policy.getRequiredUnsignedAttributes();

    return this.getCadesType(signed, unsigned);
  }

  private SignatureProfile getCadesType(final Collection<String> signed, final Collection<String> unsigned) {
    SignatureProfile type = this.cadesBes;

    if (this.hasAllAttributes(signed, PKCSObjectIdentifiers.id_aa_ets_sigPolicyId)) {
      type = this.cadesEpes;
      if ((this.hasAllAttributes(unsigned, PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) && (!this.hasAnyAttributes(unsigned, ESFAttributes.archiveTimestampV2))) {
        type = this.cadesT;
        if (this.hasAllAttributes(unsigned, PKCSObjectIdentifiers.id_aa_ets_certificateRefs, PKCSObjectIdentifiers.id_aa_ets_revocationRefs)) {
          type = this.cadesC;
          if (this.hasAllAttributes(unsigned, PKCSObjectIdentifiers.id_aa_ets_escTimeStamp)) {
            type = this.cadesX;
            if (this.hasAllAttributes(unsigned, PKCSObjectIdentifiers.id_aa_ets_revocationValues, PKCSObjectIdentifiers.id_aa_ets_certValues)) {
              type = this.cadesXl;
              if ((this.hasAllAttributes(unsigned, ESFAttributes.archiveTimestampV2)) && (!this.hasAnyAttributes(unsigned, PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, PKCSObjectIdentifiers.id_aa_ets_escTimeStamp))) {
                type = this.cadesA;
              }
            }
          }
        }
      }
    }

    return type;
  }

  private boolean hasAllAttributes(final Collection<String> set, final ASN1ObjectIdentifier... values) {
    if (set == null) {
      return false;
    }

    boolean b = true;
    for (ASN1ObjectIdentifier id : values) {
      if (!set.contains(id.getId())) {
        b = false;
        break;
      }
    }
    return b;
  }

  private boolean hasAnyAttributes(final Collection<String> set, final ASN1ObjectIdentifier... values) {
    if (set == null) {
      return false;
    }

    for (ASN1ObjectIdentifier id : values) {
      if (set.contains(id.getId())) {
        return true;
      }
    }
    return false;
  }

  public static CadesProfile getInstance() {
    return CadesProfile.instance;
  }

}
