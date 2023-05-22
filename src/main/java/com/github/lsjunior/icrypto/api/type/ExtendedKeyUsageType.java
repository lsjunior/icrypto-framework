package com.github.lsjunior.icrypto.api.type;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

public enum ExtendedKeyUsageType {

  /* @formatter:off */
  ANY("Any", KeyPurposeId.anyExtendedKeyUsage),
  SERVER_AUTH("Server Auth", KeyPurposeId.id_kp_serverAuth),
  CLIENT_AUTH("Client Auth", KeyPurposeId.id_kp_clientAuth),
  CODE_SIGN("Code Sign", KeyPurposeId.id_kp_codeSigning),
  EMAIL_PROTECTION("E-Mail Protection", KeyPurposeId.id_kp_emailProtection),
  IPSEC_END_SYSTEM("IPSEC End System", KeyPurposeId.id_kp_ipsecEndSystem),
  IPSEC_TUNNEL("IPSEC Tunnel", KeyPurposeId.id_kp_ipsecTunnel),
  IPSEC_USER("IPSEC User", KeyPurposeId.id_kp_ipsecUser),
  TIMESTAMPING("Timestamping", KeyPurposeId.id_kp_timeStamping),
  OCSP_SIGNING("OSCP Signing", KeyPurposeId.id_kp_OCSPSigning),
  DVCS("DCCS", KeyPurposeId.id_kp_dvcs),
  SBGP_CERT_AA_SERVER_AUTH("SBCP Cert AA Server Auth", KeyPurposeId.id_kp_sbgpCertAAServerAuth),
  SCVP_RESPONDER("SCVP Responder", KeyPurposeId.id_kp_scvp_responder),
  EAP_OVER_PPP("EAP Over PPP", KeyPurposeId.id_kp_eapOverPPP),
  EAP_OVER_LAN("EAP Over LAN", KeyPurposeId.id_kp_eapOverLAN),
  SCVP_SERVER("SCVP Server", KeyPurposeId.id_kp_scvpServer),
  SCVP_CLIENT("SCVP Client", KeyPurposeId.id_kp_scvpClient),
  IPSEC_IKE("IPSEC IKE", KeyPurposeId.id_kp_ipsecIKE),
  CAP_WAP_AC("CAP WAP AC", KeyPurposeId.id_kp_capwapAC),
  CAP_WAP_WTP("CAP WAP WTP", KeyPurposeId.id_kp_capwapWTP),
  SMART_CARD_LOGIN("Smart Card Login", KeyPurposeId.id_kp_smartcardlogon);
  /* @formatter:on */

  private final String label;

  private final KeyPurposeId keyPurposeId;

  private ExtendedKeyUsageType(final String label, final KeyPurposeId keyPurposeId) {
    this.label = label;
    this.keyPurposeId = keyPurposeId;
  }

  @Override
  public String toString() {
    return this.label;
  }

  public KeyPurposeId getKeyPurposeId() {
    return this.keyPurposeId;
  }

  public static ExtendedKeyUsageType get(final KeyPurposeId keyPurposeId) {
    if (keyPurposeId == null) {
      return null;
    }
    for (ExtendedKeyUsageType eku : ExtendedKeyUsageType.values()) {
      if (eku.getKeyPurposeId().equals(keyPurposeId)) {
        return eku;
      }
    }
    return null;
  }

  public static ExtendedKeyUsageType get(final ASN1ObjectIdentifier asn1ObjectIdentifier) {
    if (asn1ObjectIdentifier != null) {
      for (ExtendedKeyUsageType eku : ExtendedKeyUsageType.values()) {
        if (eku.getKeyPurposeId().getId().equals(asn1ObjectIdentifier.getId())) {
          return eku;
        }
      }
    }
    return null;
  }

}
