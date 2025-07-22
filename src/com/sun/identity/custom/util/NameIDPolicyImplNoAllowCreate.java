package com.sun.identity.custom.util;

import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2SDKUtils;
import com.sun.identity.saml2.protocol.NameIDPolicy;
import com.sun.identity.saml2.protocol.impl.NameIDPolicyImpl;
import com.sun.identity.shared.xml.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class NameIDPolicyImplNoAllowCreate extends NameIDPolicyImpl implements NameIDPolicy {

  private static final String FORMAT = "Format";

  private static final String SPNAMEQUALIFIER = "SPNameQualifier";

  private static final String ALLOWCREATE = "AllowCreate";

  private boolean isMutable = false;

  private String format;

  private String spNameQualifier;

  private Boolean allowCreate;

  public NameIDPolicyImplNoAllowCreate() {
    this.isMutable = true;
  }

  public NameIDPolicyImplNoAllowCreate(Element element) throws SAML2Exception {
    parseElement(element);
  }

  public NameIDPolicyImplNoAllowCreate(String xmlString) throws SAML2Exception {
    Document xmlDocument = XMLUtils.toDOMDocument(xmlString);
    if (xmlDocument == null)
      throw new SAML2Exception(SAML2SDKUtils.bundle
          .getString("errorObtainingElement"));
    parseElement(xmlDocument.getDocumentElement());
  }

  public void removeAllowCreate() {
    this.allowCreate = null;
  }

  private void parseElement(Element element) {
    this.format = element.getAttribute("Format");
    this.spNameQualifier = element.getAttribute("SPNameQualifier");
    String allowCreateStr = element.getAttribute("AllowCreate");
    if (allowCreateStr != null && allowCreateStr.length() > 0)
      this.allowCreate = SAML2SDKUtils.booleanValueOf(allowCreateStr);
  }
}
