/**
 * UserObjectIDM.java
 */

package com.sun.identity.custom.util;

import org.json.JSONException;
import org.json.JSONObject;

//import jdk.nashorn.internal.parser.JSONParser;

public class UserObjectIDM  implements java.io.Serializable {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private java.lang.String _id;

    private java.lang.String userName;

    private java.lang.String accountStatus;

    private java.lang.String postalCode;

    private java.lang.String stateProvince;

    private java.lang.String postaltelephoneNumberOffice;

    private java.lang.String telephoneNumberOffice2;

    private java.lang.String country;

    private java.lang.String city;

    private java.lang.String givenuserName;

    private java.lang.String description;

    private java.lang.String sn;

    private java.lang.String telephoneNumber;

    private java.lang.String mail;

    private java.lang.String telephoneNumberOffice;

    private java.lang.String enteAppartenenza;

    private java.lang.String ufficioAppartenenza;

    private java.lang.String amministrazioneAppartenenza;
    
    private java.lang.String birthDate;
    
    private java.lang.String codiceFiscale;
    
    private java.lang.String userType;
    
    public UserObjectIDM() {
    }

    public UserObjectIDM(
           java.lang.String _id,
           java.lang.String userName,
           java.lang.String accountStatus,
           java.lang.String postalCode,
           java.lang.String stateProvince,
           java.lang.String postaltelephoneNumberOffice,
           java.lang.String telephoneNumberOffice2,
           java.lang.String country,
           java.lang.String city,
           java.lang.String givenuserName,
           java.lang.String description,
           java.lang.String sn,
           java.lang.String telephoneNumber,
           java.lang.String mail,
           java.lang.String telephoneNumberOffice,
           java.lang.String enteAppartenenza,
           java.lang.String ufficioAppartenenza,
           java.lang.String amministrazioneAppartenenza,
           java.lang.String birthDate,
           java.lang.String codiceFiscale,
    	   java.lang.String userType) {
           this._id = _id;
           this.userName = userName;
           this.accountStatus = accountStatus;
           this.postalCode = postalCode;
           this.stateProvince = stateProvince;
           this.postaltelephoneNumberOffice = postaltelephoneNumberOffice;
           this.telephoneNumberOffice2 = telephoneNumberOffice2;
           this.country = country;
           this.city = city;
           this.givenuserName = givenuserName;
           this.description = description;
           this.sn = sn;
           this.telephoneNumber = telephoneNumber;
           this.mail = mail;
           this.telephoneNumberOffice = telephoneNumberOffice;
           this.enteAppartenenza = enteAppartenenza;
           this.ufficioAppartenenza = ufficioAppartenenza;
           this.amministrazioneAppartenenza = amministrazioneAppartenenza;
           this.birthDate = birthDate;
           this.codiceFiscale = codiceFiscale;
           this.userType = userType;
    }


    /**
     * Gets the _id value for this UserObjectIDM.
     * 
     * @return _id
     */
    public java.lang.String get_id() {
        return _id;
    }


    /**
     * Sets the _id value for this UserObjectIDM.
     * 
     * @param _id
     */
    public void set_id(java.lang.String _id) {
        this._id = _id;
    }


    /**
     * Gets the userName value for this UserObjectIDM.
     * 
     * @return userName
     */
    public java.lang.String getuserName() {
        return userName;
    }


    /**
     * Sets the userName value for this UserObjectIDM.
     * 
     * @param userName
     */
    public void setuserName(java.lang.String userName) {
        this.userName = userName;
    }


    /**
     * Gets the accountStatus value for this UserObjectIDM.
     * 
     * @return accountStatus
     */
    public java.lang.String getaccountStatus() {
        return accountStatus;
    }


    /**
     * Sets the accountStatus value for this UserObjectIDM.
     * 
     * @param accountStatus
     */
    public void setaccountStatus(java.lang.String accountStatus) {
        this.accountStatus = accountStatus;
    }


    /**
     * Gets the postalCode value for this UserObjectIDM.
     * 
     * @return postalCode
     */
    public java.lang.String getpostalCode() {
        return postalCode;
    }


    /**
     * Sets the postalCode value for this UserObjectIDM.
     * 
     * @param postalCode
     */
    public void setpostalCode(java.lang.String postalCode) {
        this.postalCode = postalCode;
    }


    /**
     * Gets the stateProvince value for this UserObjectIDM.
     * 
     * @return stateProvince
     */
    public java.lang.String getstateProvince() {
        return stateProvince;
    }


    /**
     * Sets the stateProvince value for this UserObjectIDM.
     * 
     * @param stateProvince
     */
    public void setstateProvince(java.lang.String stateProvince) {
        this.stateProvince = stateProvince;
    }


    /**
     * Gets the postaltelephoneNumberOffice value for this UserObjectIDM.
     * 
     * @return postaltelephoneNumberOffice
     */
    public java.lang.String getpostaltelephoneNumberOffice() {
        return postaltelephoneNumberOffice;
    }


    /**
     * Sets the postaltelephoneNumberOffice value for this UserObjectIDM.
     * 
     * @param postaltelephoneNumberOffice
     */
    public void setpostaltelephoneNumberOffice(java.lang.String postaltelephoneNumberOffice) {
        this.postaltelephoneNumberOffice = postaltelephoneNumberOffice;
    }


    /**
     * Gets the telephoneNumberOffice2 value for this UserObjectIDM.
     * 
     * @return telephoneNumberOffice2
     */
    public java.lang.String gettelephoneNumberOffice2() {
        return telephoneNumberOffice2;
    }


    /**
     * Sets the telephoneNumberOffice2 value for this UserObjectIDM.
     * 
     * @param telephoneNumberOffice2
     */
    public void settelephoneNumberOffice2(java.lang.String telephoneNumberOffice2) {
        this.telephoneNumberOffice2 = telephoneNumberOffice2;
    }


    /**
     * Gets the country value for this UserObjectIDM.
     * 
     * @return country
     */
    public java.lang.String getcountry() {
        return country;
    }


    /**
     * Sets the country value for this UserObjectIDM.
     * 
     * @param country
     */
    public void setcountry(java.lang.String country) {
        this.country = country;
    }


    /**
     * Gets the city value for this UserObjectIDM.
     * 
     * @return city
     */
    public java.lang.String getcity() {
        return city;
    }


    /**
     * Sets the city value for this UserObjectIDM.
     * 
     * @param city
     */
    public void setcity(java.lang.String city) {
        this.city = city;
    }


    /**
     * Gets the givenuserName value for this UserObjectIDM.
     * 
     * @return givenuserName
     */
    public java.lang.String getgivenuserName() {
        return givenuserName;
    }


    /**
     * Sets the givenuserName value for this UserObjectIDM.
     * 
     * @param givenuserName
     */
    public void setgivenuserName(java.lang.String givenuserName) {
        this.givenuserName = givenuserName;
    }


    /**
     * Gets the description value for this UserObjectIDM.
     * 
     * @return description
     */
    public java.lang.String getdescription() {
        return description;
    }


    /**
     * Sets the description value for this UserObjectIDM.
     * 
     * @param description
     */
    public void setdescription(java.lang.String description) {
        this.description = description;
    }


    /**
     * Gets the sn value for this UserObjectIDM.
     * 
     * @return sn
     */
    public java.lang.String getsn() {
        return sn;
    }


    /**
     * Sets the sn value for this UserObjectIDM.
     * 
     * @param sn
     */
    public void setsn(java.lang.String sn) {
        this.sn = sn;
    }


    /**
     * Gets the telephoneNumber value for this UserObjectIDM.
     * 
     * @return telephoneNumber
     */
    public java.lang.String gettelephoneNumber() {
        return telephoneNumber;
    }


    /**
     * Sets the telephoneNumber value for this UserObjectIDM.
     * 
     * @param telephoneNumber
     */
    public void settelephoneNumber(java.lang.String telephoneNumber) {
        this.telephoneNumber = telephoneNumber;
    }


    /**
     * Gets the mail value for this UserObjectIDM.
     * 
     * @return mail
     */
    public java.lang.String getmail() {
        return mail;
    }


    /**
     * Sets the mail value for this UserObjectIDM.
     * 
     * @param mail
     */
    public void setmail(java.lang.String mail) {
        this.mail = mail;
    }


    /**
     * Gets the telephoneNumberOffice value for this UserObjectIDM.
     * 
     * @return telephoneNumberOffice
     */
    public java.lang.String gettelephoneNumberOffice() {
        return telephoneNumberOffice;
    }


    /**
     * Sets the telephoneNumberOffice value for this UserObjectIDM.
     * 
     * @param telephoneNumberOffice
     */
    public void settelephoneNumberOffice(java.lang.String telephoneNumberOffice) {
        this.telephoneNumberOffice = telephoneNumberOffice;
    }


    /**
     * Gets the enteAppartenenza value for this UserObjectIDM.
     * 
     * @return enteAppartenenza
     */
    public java.lang.String getenteAppartenenza() {
        return enteAppartenenza;
    }


    /**
     * Sets the enteAppartenenza value for this UserObjectIDM.
     * 
     * @param enteAppartenenza
     */
    public void setenteAppartenenza(java.lang.String enteAppartenenza) {
        this.enteAppartenenza = enteAppartenenza;
    }


    /**
     * Gets the ufficioAppartenenza value for this UserObjectIDM.
     * 
     * @return ufficioAppartenenza
     */
    public java.lang.String getufficioAppartenenza() {
        return ufficioAppartenenza;
    }


    /**
     * Sets the ufficioAppartenenza value for this UserObjectIDM.
     * 
     * @param ufficioAppartenenza
     */
    public void setufficioAppartenenza(java.lang.String ufficioAppartenenza) {
        this.ufficioAppartenenza = ufficioAppartenenza;
    }

    /**
     * Gets the amministrazioneAppartenenza value for this UserObjectIDM.
     * 
     * @return amministrazioneAppartenenza
     */
	public java.lang.String getAmministrazioneAppartenenza() {
		return amministrazioneAppartenenza;
	}

    /**
     * Sets the amministrazioneAppartenenza value for this UserObjectIDM.
     * 
     * @param amministrazioneAppartenenza
     */
	public void setAmministrazioneAppartenenza(java.lang.String amministrazioneAppartenenza) {
		this.amministrazioneAppartenenza = amministrazioneAppartenenza;
	}

    /**
     * Gets the birthDate value for this UserObjectIDM.
     * 
     * @return birthDate
     */
	public java.lang.String getBirthDate() {
		return birthDate;
	}

    /**
     * Sets the birthDate value for this UserObjectIDM.
     * 
     * @param birthDate
     */
	public void setBirthDate(java.lang.String birthDate) {
		this.birthDate = birthDate;
	}

    /**
     * Gets the codiceFiscale value for this UserObjectIDM.
     * 
     * @return codiceFiscale
     */
	public java.lang.String getCodiceFiscale() {
		return codiceFiscale;
	}

    /**
     * Sets the codiceFiscale value for this UserObjectIDM.
     * 
     * @param codiceFiscale
     */
	public void setCodiceFiscale(java.lang.String codiceFiscale) {
		this.codiceFiscale = codiceFiscale;
	}

    /**
     * Gets the userType value for this UserObjectIDM.
     * 
     * @return userType
     */
	public java.lang.String getUserType() {
		return userType;
	}

    /**
     * Sets the userType value for this UserObjectIDM.
     * 
     * @param userType
     */
	public void setUserType(java.lang.String userType) {
		this.userType = userType;
	}

	/**
	 * Creating toString
	 */
    public String toString() 
    { 
        return "UserObjectIDM [_id="
                + _id 
                + ", userName="
                + userName 
                + ", accountStatus="
                + accountStatus 
                + ", postalCode="
                + postalCode 
                + ", stateProvince="
                + stateProvince 
                + ", postaltelephoneNumberOffice="
                + postaltelephoneNumberOffice 
                + ", telephoneNumberOffice2="
                + telephoneNumberOffice2 
                + ", country="
                + country 
                + ", city="
                + city 
                + ", givenuserName="
                + givenuserName 
                + ", description="
                + description 
                + ", sn="
                + sn 
                + ", telephoneNumber="
                + telephoneNumber 
                + ", mail="
                + mail 
                + ", telephoneNumberOffice="
                + telephoneNumberOffice 
                + ", enteAppartenenza="
                + enteAppartenenza 
                + ", ufficioAppartenenza="
                + ufficioAppartenenza 
                + ", amministrazioneAppartenenza="
                + amministrazioneAppartenenza 
                + ", birthDate="
                + birthDate 
                + ", codiceFiscale="
                + codiceFiscale 
                + ", userType="
                + userType + "]"; 
    } 
    
	/**
	 * Creating JSON To Object
	 * @throws JSONException 
	 */
    public boolean JSONtoObject(String sJSON) throws JSONException 
    { 
    	if( sJSON == null ){
    		return false;
    	}
//    	JSONParser parser = new JSONParser(sJSON);
//	    JSONObject jsonObject = (JSONObject) parser.parse(sJSON);
    	UserObjectIDM userJSON = new UserObjectIDM();
    	JSONObject tomJsonObject = new JSONObject(sJSON);
    	String[] myData = sJSON.split(",");
    	for (String s: myData) {
    	    System.out.println(s);
    	}
		return false;
    	
/* {  
 * "result" : [ 
 * 		{    
 * 			"_id" : "d39ca46f-f154-444b-9b62-27a27a5dcf91",    
 * 			"_rev" : "28",    
 * 			"userName" : "dpace",    
 * 			"accountStatus" : "active",    
 * 			"postalCode" : null,    
 * 			"givenName" : "Domenico",    
 * 			"description" : "Domenico Pace",    
 * 			"sn" : "Pace",    
 * 			"telephoneNumber" : null,    
 * 			"mail" : "domenico.pace@dxc.com",    
 * 			"kbaInfo" : null,    
 * 			"preferences" : null,    
 * 			"consentedMappings" : null,    
 * 			"effectiveAssignments" : [ ],    
 * 			"effectiveRoles" : [ ],    
 * 			"cdmIdUtente" : "2531778",    
 * 			"cdmgiuridicaFisica" : "F",    
 * 			"createdOn" : "01/06/2020",    "gender" : "M",    "BirthDate" : "19810627000000",    "BirtyMunicipality" : "Castrovillari",    "BirthProvince" : "CS",    "cdmCodiceFiscale" : "PCADNC81H27C349R",    
 * 			"BirthCountry" : null,    "countryCode" : null,    "cdmTipoUtente" : "pin",    "cdmFasciaEta" : null,    "cdmProfessione" : null,    "mobile" : null,    "fax" : null,    
 * 			"ResidenceProvince" : null,    "cdmResidenzaCodiceComune" : null,    "cdmNascitaCodiceComune" : "C349",    "ResidenceAddress" : null,    "ResidenceMunicipality" : null,    
 * 			"cdmTipoStreet" : null,    "cdmCivico" : null,    "cdmBarrato" : null,    "cdmTipoPin" : null,    "cdmPin" : null,    "cdmCO" : null,    "cdmCoCAP" : null,    "cdmCoComune" : null,   
 * 			 "cdmCoVia" : null,    "cdmCoNazione" : null,    "cdmCoCivico" : null,    "cdmCoProvincia" : null,    "cdmCoBarrato" : null,    "Resident" : null,    "cdmSIPOCheckedOn" : "",    
 * 			 "updatedON" : "15/06/2020",    "cdmConsensoPrivacyTerzi" : "true",    "SPIDemail" : null,    "employeeType" : null,    "PecEmail" : null,    "SPIDMobile" : null  
 *  	}
 *  ],  
 *  "resultCount" : 1,  
 *  "pagedResultsCookie" : null,  
 *  "totalPagedResultsPolicy" : "NONE",  
 *  "totalPagedResults" : -1,  
 *  "remainingPagedResults" : -1
 *  }

  */
    }
    
    private java.lang.Object __equalsCalc = null;
    @SuppressWarnings("unused")
	public synchronized boolean equals(java.lang.Object obj) {
        if (!(obj instanceof UserObjectIDM)) return false;
        UserObjectIDM other = (UserObjectIDM) obj;
        if (obj == null) return false;
        if (this == obj) return true;
        if (__equalsCalc != null) {
            return (__equalsCalc == obj);
        }
        __equalsCalc = obj;
        boolean _equals;
        _equals = true && 
            ((this._id==null && other.get_id()==null) || 
             (this._id!=null &&
              this._id.equals(other.get_id()))) &&
            ((this.userName==null && other.getuserName()==null) || 
             (this.userName!=null &&
              this.userName.equals(other.getuserName()))) &&
            ((this.accountStatus==null && other.getaccountStatus()==null) || 
             (this.accountStatus!=null &&
              this.accountStatus.equals(other.getaccountStatus()))) &&
            ((this.postalCode==null && other.getpostalCode()==null) || 
             (this.postalCode!=null &&
              this.postalCode.equals(other.getpostalCode()))) &&
            ((this.stateProvince==null && other.getstateProvince()==null) || 
             (this.stateProvince!=null &&
              this.stateProvince.equals(other.getstateProvince()))) &&
            ((this.postaltelephoneNumberOffice==null && other.getpostaltelephoneNumberOffice()==null) || 
             (this.postaltelephoneNumberOffice!=null &&
              this.postaltelephoneNumberOffice.equals(other.getpostaltelephoneNumberOffice()))) &&
            ((this.telephoneNumberOffice2==null && other.gettelephoneNumberOffice2()==null) || 
             (this.telephoneNumberOffice2!=null &&
              this.telephoneNumberOffice2.equals(other.gettelephoneNumberOffice2()))) &&
            ((this.country==null && other.getcountry()==null) || 
             (this.country!=null &&
              this.country.equals(other.getcountry()))) &&
            ((this.city==null && other.getcity()==null) || 
             (this.city!=null &&
              this.city.equals(other.getcity()))) &&
            ((this.givenuserName==null && other.getgivenuserName()==null) || 
             (this.givenuserName!=null &&
              this.givenuserName.equals(other.getgivenuserName()))) &&
            ((this.description==null && other.getdescription()==null) || 
             (this.description!=null &&
              this.description.equals(other.getdescription()))) &&
            ((this.sn==null && other.getsn()==null) || 
             (this.sn!=null &&
              this.sn.equals(other.getsn()))) &&
            ((this.telephoneNumber==null && other.gettelephoneNumber()==null) || 
             (this.telephoneNumber!=null &&
              this.telephoneNumber.equals(other.gettelephoneNumber()))) &&
            ((this.mail==null && other.getmail()==null) || 
             (this.mail!=null &&
              this.mail.equals(other.getmail()))) &&
            ((this.telephoneNumberOffice==null && other.gettelephoneNumberOffice()==null) || 
             (this.telephoneNumberOffice!=null &&
              this.telephoneNumberOffice.equals(other.gettelephoneNumberOffice()))) &&
            ((this.enteAppartenenza==null && other.getenteAppartenenza()==null) || 
             (this.enteAppartenenza!=null &&
              this.enteAppartenenza.equals(other.getenteAppartenenza()))) &&
            ((this.ufficioAppartenenza==null && other.getufficioAppartenenza()==null) || 
             (this.ufficioAppartenenza!=null &&
              this.ufficioAppartenenza.equals(other.getufficioAppartenenza()))) &&
	        ((this.amministrazioneAppartenenza==null && other.getAmministrazioneAppartenenza()==null) || 
            (this.amministrazioneAppartenenza!=null &&
             this.amministrazioneAppartenenza.equals(other.getAmministrazioneAppartenenza()))) &&
	        ((this.birthDate==null && other.getBirthDate()==null) || 
            (this.birthDate!=null &&
             this.birthDate.equals(other.getBirthDate()))) && 
	        ((this.codiceFiscale==null && other.getCodiceFiscale()==null) || 
            (this.codiceFiscale!=null &&
             this.codiceFiscale.equals(other.getCodiceFiscale()))) &&
	        ((this.userType==null && other.getuserName()==null) ||  
            (this.userType!=null &&
             this.userType.equals(other.getuserName())));

        __equalsCalc = null;
        return _equals;
    }

    private boolean __hashCodeCalc = false;
    public synchronized int hashCode() {
        if (__hashCodeCalc) {
            return 0;
        }
        __hashCodeCalc = true;
        int _hashCode = 1;
        if (get_id() != null) {
            _hashCode += get_id().hashCode();
        }
        if (getuserName() != null) {
            _hashCode += getuserName().hashCode();
        }
        if (getaccountStatus() != null) {
            _hashCode += getaccountStatus().hashCode();
        }
        if (getpostalCode() != null) {
            _hashCode += getpostalCode().hashCode();
        }
        if (getstateProvince() != null) {
            _hashCode += getstateProvince().hashCode();
        }
        if (getpostaltelephoneNumberOffice() != null) {
            _hashCode += getpostaltelephoneNumberOffice().hashCode();
        }
        if (gettelephoneNumberOffice2() != null) {
            _hashCode += gettelephoneNumberOffice2().hashCode();
        }
        if (getcountry() != null) {
            _hashCode += getcountry().hashCode();
        }
        if (getcity() != null) {
            _hashCode += getcity().hashCode();
        }
        if (getgivenuserName() != null) {
            _hashCode += getgivenuserName().hashCode();
        }
        if (getdescription() != null) {
            _hashCode += getdescription().hashCode();
        }
        if (getsn() != null) {
            _hashCode += getsn().hashCode();
        }
        if (gettelephoneNumber() != null) {
            _hashCode += gettelephoneNumber().hashCode();
        }
        if (getmail() != null) {
            _hashCode += getmail().hashCode();
        }
        if (gettelephoneNumberOffice() != null) {
            _hashCode += gettelephoneNumberOffice().hashCode();
        }
        if (getenteAppartenenza() != null) {
            _hashCode += getenteAppartenenza().hashCode();
        }
        if (getufficioAppartenenza() != null) {
            _hashCode += getufficioAppartenenza().hashCode();
        }
        if (getAmministrazioneAppartenenza() != null) {
            _hashCode += getAmministrazioneAppartenenza().hashCode();
        }
        if (getBirthDate() != null) {
            _hashCode += getBirthDate().hashCode();
        }
        if (getCodiceFiscale() != null) {
            _hashCode += getCodiceFiscale().hashCode();
        }
        if (getUserType() != null) {
            _hashCode += getUserType().hashCode();
        }

        __hashCodeCalc = false;
        return _hashCode;
    }

}
