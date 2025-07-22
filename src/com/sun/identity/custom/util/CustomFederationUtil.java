package com.sun.identity.custom.util;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.assertion.AttributeStatement;
import com.sun.identity.saml2.assertion.EncryptedAttribute;
import com.sun.identity.saml2.assertion.EncryptedID;
import com.sun.identity.saml2.assertion.NameID;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.key.KeyUtil;
import com.sun.identity.saml2.meta.SAML2MetaException;

public class CustomFederationUtil {
	private static com.sun.identity.shared.debug.Debug debug = null;
	private static String DBGNAME = "CustomFederationUtil";
	
	private Set<PrivateKey> decryptionKey = null;

	public CustomFederationUtil() {
		if (debug == null){
			debug = com.sun.identity.shared.debug.Debug.getInstance(DBGNAME);
		}
	}

	public NameID getNameID(Assertion assertion, String hostEntityID, String realm){
		String method = "[getNameID]:: ";

		NameID nameID = null;
		try {
			EncryptedID encryptedID = assertion.getSubject().getEncryptedID();
			if (encryptedID != null){
				decryptionKey = (Set<PrivateKey>) KeyUtil.getDecryptionKeys(SAML2Utils.getSAML2MetaManager().getSPSSOConfig(realm, hostEntityID));
				nameID = encryptedID.decrypt(decryptionKey);
			}else{
				nameID = assertion.getSubject().getNameID();
			}
		} catch (SAML2MetaException e1) {
			debug.error(method + "SAML2MetaException: ", e1);
		} catch (SAML2Exception e) {
			debug.error(method + "SAML2Exception: ", e);
		}
		return nameID;
	}
	
	public Object getAssertionAttribute(String realm, String entityID, Assertion assertion, String attrName) throws SAML2Exception {
		String method = "[getAssertionAttribute]:: ";

		List<?> attributeStatements = assertion.getAttributeStatements();
		if (attributeStatements == null || attributeStatements.size() == 0){
			if (debug.errorEnabled()){
				debug.message(method + "Assertion does not have attribute statements.");
			}
			return null;
		}

		List<?> attributeValue = null;
		Iterator<?> iter = attributeStatements.iterator();

		while (iter.hasNext()){

			AttributeStatement statement = (AttributeStatement) iter.next();
			attributeValue = getAttribute(statement, attrName, realm, entityID);
			if (attributeValue != null && !attributeValue.isEmpty()){
				break;
			}
		}

		if (attributeValue == null || attributeValue.isEmpty()){
			if (debug.errorEnabled()){
				debug.error(method + "attribute is not specified in the assertion.");
			}
			return null;
		}
		return attributeValue;
	}


	private List<?> getAttribute(AttributeStatement statement, String attributeName, String realm, String hostEntityID) {
		String method = "[getAttribute]:: ";

		// check it if the attribute needs to be encrypted?
		List<Attribute> list = statement.getAttribute();
		List<?> encList = statement.getEncryptedAttribute();
		if (encList != null && encList.size() != 0){
			// a new list to hold the union of clear and encrypted attributes
			List<Attribute> allList = new ArrayList<Attribute>();
			if (list != null && !list.isEmpty()){
				allList.addAll(list);
			}
			list = allList;
			for (Iterator<?> encIter = encList.iterator(); encIter.hasNext();){
				try{
					if (decryptionKey == null){
						decryptionKey = (Set<PrivateKey>) KeyUtil.getDecryptionKeys(SAML2Utils.getSAML2MetaManager().getSPSSOConfig(realm, hostEntityID));
					}
					list.add(((EncryptedAttribute) encIter.next()).decrypt(decryptionKey));
				}catch (SAML2Exception se){
					debug.error(method + "Decryption error:", se);
					return null;
				}
			}
		}

		for (Iterator<Attribute> iter = list.iterator(); iter.hasNext();){
			Attribute attribute = iter.next();
			if (!attributeName.equalsIgnoreCase(attribute.getName())){
				continue;
			}

			List<?> values = attribute.getAttributeValueString();
			if (values == null || values.size() == 0){
				return null;
			}
			return values;
		}
		return null;
	}

	public List<?> getAttributeVal(List<Attribute> lattribute, String attributeName) {
//		String method = "[getAttributeVal]:: ";
/*
		List<?> values = null;
		int index = lattribute.indexOf(attributeName);
		if(index > 0)
			values = lattribute.get(index).getAttributeValueString();
		return values;
*/	
		for (Iterator<Attribute> iter = lattribute.iterator(); iter.hasNext();){
			Attribute attribute = iter.next();
			if (!attributeName.equalsIgnoreCase(attribute.getName())){
				continue;
			}

			List<?> values = attribute.getAttributeValueString();
			if (values == null || values.size() == 0){
				return null;
			}
			return values;
		}
		
		return null;
	}
	
}
