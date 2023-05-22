package com.github.lsjunior.icrypto.core.signature.pades;

import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.imageio.ImageIO;

import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.io.ByteSource;

public abstract class AbstractPadesService implements PadesService {

  public AbstractPadesService() {
    super();
  }

  protected BufferedImage getSignatureImage(final PadesSignatureParameters parameters) throws IOException {
    VisibleSignatureParameters visibleSignature = parameters.getVisibleSignature();
    Identity identity = parameters.getIdentity();
    X509Certificate certificate = (X509Certificate) identity.getChain().get(0);
    String subject = Certificates.toString(certificate.getSubjectX500Principal());
    String issuer = Certificates.toString(certificate.getIssuerX500Principal());
    String date = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date());

    // Remove o : dos certificados ICP
    subject = Splitter.on(':').split(subject).iterator().next();

    BufferedImage bufferedImage = new BufferedImage(visibleSignature.getWidth() * 2, visibleSignature.getHeight() * 2, BufferedImage.TYPE_INT_RGB);
    Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
    g.setColor(Color.WHITE);
    g.fillRect(0, 0, bufferedImage.getWidth(), bufferedImage.getHeight());

    int left = 4;
    ByteSource logo = visibleSignature.getImage();
    if (logo != null) {
      BufferedImage tmp = ImageIO.read(logo.openStream());
      g.drawImage(tmp, 4, 4, null);
      g.setComposite(AlphaComposite.Clear);
      left = tmp.getWidth() + 10;
    }

    int top = 0;
    int lineHeight = 24; // FIXME
    int fontSize = 12;
    g.setColor(Color.BLACK);
    g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
    g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
    g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
    g.setComposite(AlphaComposite.Src);

    // FIXME Delegar!!!
    g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, fontSize + 2));
    g.drawString("Documento assinado digitalmente", left, top += lineHeight);
    g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, fontSize));
    g.drawString("Certificado: " + subject, left, top += lineHeight);
    g.drawString("Emissor: " + issuer, left, top += lineHeight);
    g.drawString("Data e Hora da Assinatura: " + date, left, top += lineHeight);
    // g.drawString("® iCrypto um produto Lidersis", left, top += lineHeight);
    if (!Strings.isNullOrEmpty(parameters.getProductInfo())) {
      g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, fontSize));
      g.drawString(parameters.getProductInfo(), left, top += lineHeight);
    }

    g.setColor(new Color(224, 224, 224));
    // g.setStroke(new BasicStroke(1));
    g.drawRect(0, 0, bufferedImage.getWidth() - 1, bufferedImage.getHeight() - 1);

    g.dispose();

    return bufferedImage;
  }

  protected String getSignatureHtml(final PadesSignatureParameters parameters) {
    VisibleSignatureParameters visibleSignature = parameters.getVisibleSignature();
    String template = visibleSignature.getTemplate();
    Identity identity = parameters.getIdentity();
    Date now = new Date();
    X509Certificate certificate = (X509Certificate) identity.getChain().get(0);
    String subject = Certificates.toString(certificate.getSubjectX500Principal());
    String issuer = Certificates.toString(certificate.getIssuerX500Principal());
    String dateAndTime = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(now);
    String date = new SimpleDateFormat("dd/MM/yyyy").format(now);
    String time = new SimpleDateFormat("HH:mm:ss").format(now);

    // Remove o : dos certificados ICP
    subject = Splitter.on(':').split(subject).iterator().next();

    template = template.replaceAll("\\$\\{certificate\\}", subject);
    template = template.replaceAll("\\$\\{issuer\\}", issuer);
    template = template.replaceAll("\\$\\{dateAndTime\\}", dateAndTime);
    template = template.replaceAll("\\$\\{date\\}", date);
    template = template.replaceAll("\\$\\{time\\}", time);
    if (!Strings.isNullOrEmpty(parameters.getProductInfo())) {
      template += "<div style=\"font-size: 4px; font-weight: bold;\">" + parameters.getProductInfo() + "</div>";
    }
    return template;
  }

}
