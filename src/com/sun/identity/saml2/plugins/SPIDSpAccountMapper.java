package com.sun.identity.saml2.plugins;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.api.client.util.ArrayMap;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOException;
import com.sun.identity.custom.util.CustomFederationUtil;
import com.sun.identity.custom.util.CustomRepoUtil;
import com.sun.identity.custom.util.CustomRestUtil;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.assertion.AttributeStatement;
import com.sun.identity.saml2.assertion.NameID;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.jaxb.entityconfig.IDPSSOConfigElement;
import com.sun.identity.saml2.jaxb.entityconfig.SPSSOConfigElement;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.meta.SAML2MetaUtils;
import com.sun.identity.saml2.protocol.Response;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static com.sun.identity.saml2.plugins.DefaultAttributeMapper.SP;

/**
 * This class <code>DefaultSPAccountMapper</code> is the default implementation
 * of the <code>DefaultLibrarySPAccountMapper</code> that is used to map the
 * <code>SAML</code> protocol objects to the user accounts. at the
 * <code>ServiceProvider</code> side of SAML v2 plugin. Custom implementations
 * may extend from this class to override some of these implementations if they
 * choose to do so.
 *
 * @param <ele>
 */
public class SPIDSpAccountMapper<ele> extends DefaultLibrarySPAccountMapper {
    // private PrivateKey decryptionKey = null;
    private static final String JAR_VERSION = "6.8"; // TODO

    /**
     * Regole di compilazione della console OpenAM:
     * aggiungere i seguenti attributi globali nelle advanced properties (Configure
     * > Server Defaults > Advanced)
     * - spid.createuser.enable : se deve essere abilitata la creazione utente
     * - spid.createuser.ws : se deve essere abilitata la creazione utente via WS
     * specificare l'url del servizio
     * - spid.createuser.static.attribute: specifica una lista di attributi statici
     * da popolare in creazione dell'utenza
     * - spid.createuser.create.cdm.attribute.flag : flag specifico per il Comune di
     * Milano - se abilitato imposta degli attributi specifici //CDM
     * - spid.searchuser.flag: se abilitato ricerca l'utente
     * - spid.searchuser.attribute: se abilitato il flag precedente specificare
     * l'attributo per la ricerca utente cittadino EX.
     * uid=spidCode;cdmCodiceFiscale=fiscalNumber
     * - spid.searchpiva.attribute: se abilitato il flag precedente specificare
     * l'attributo per la ricerca utenti partita iva EX. cdmPartitaIva=ivaCode
     * PER IDM
     * - spid.createuser.idm.ws : se deve essere abilitata la creazione utente via
     * WS IDM specificare l'url del servizio
     * - spid.idm.ws.credential.user : utenza per chiamate rest IDM
     * - spid.idm.ws.credential.password : password per chiamate rest IDM
     */
    // add these attributes as advanced properties for CREATE USER FUNCTION
    private static final String GLOBAL_PROP_CREATEUSER_ENABLE = "spid.createuser.enable";
    private static final String GLOBAL_PROP_CREATEUSER_BASEDN = "spid.createuser.enable.basedn";
    private static final String GLOBAL_PROP_CREATEUSER_WS = "spid.createuser.ws";
    private static final String GLOBAL_PROP_CREATEUSER_ATTRIBUTE = "spid.createuser.static.attribute";
    private static final String GLOBAL_PROP_UPDATEUSER_ATTRIBUTE = "spid.updateuser.static.attribute";
    private static final String GLOBAL_PROP_CREATEUSER_SETCDMATTR = "spid.createuser.create.cdm.attribute.flag";
    /*
     * se impostato a true aggiorna lo stato utente ad Active ad ogni accesso SPID
     */
    private static final String GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS = "spid.updateuser.enable.cdm.status.flag";
    /*
     * se impostato a true abilita la logica di aggiornamento utente ad ogni accesso
     * SPID
     */
    private static final String GLOBAL_PROP_UPDATEUSER_FLAG = "spid.updateuser.enable.cdm.flag";

    /*
     * searchuser attribute -> Innesca la ricerca e gestione di account SPID
     * pregressi. La ricerca � in AND
     * attrLDAP=attrAsserzione, oppure attrLDAP=$stringafissa (inserire il dollaro).
     * Ad esempio cdmCodiceFiscale=fiscalNumber;cdmTipoUtente=$3
     */
    private static final String GLOBAL_PROP_SEARCHUSER_ATTR = "spid.searchuser.attribute";

    private static final String GLOBAL_PROP_SEARCHPIVA_ATTR = "spid.searchpiva.attribute"; // Aggiunto per gestione
                                                                                           // partita iva

    // Aggiunto per chiamate REST IDM
    private static final String GLOBAL_PROP_CREATEIDMUSER_WS = "spid.createuser.idm.ws"; // "https://openidm.test.comune/openidm"
    private static final String GLOBAL_PROP_IDMWS_USER = "spid.idm.ws.credential.user"; // "openidm-attributeMapper"
    private static final String GLOBAL_PROP_IDMWS_PWD = "spid.idm.ws.credential.password"; // "password"

    // Aggiunto per chiamate REST IDM per interrogare il managed dei comuni ->
    // modifica per toponomastica
    private static final String GLOBAL_PROP_CREATEIDMUSER_WS_COMUNI = "spid.createuser.idm.ws.comuni";

    private static Boolean createUserEnable = false;
    /* CDM */
    private static Boolean setCDMAttribute = false;
    private static Boolean updateCDMStatus = false;
    private static Boolean updateCDMUser = false;
    private final static String SPID_CDM_GIURIDICA_FISICA = "cdmGiuridicaFisica";

    private static String createUserWs;

    private static String searchUserAttr;
    private static String searchPivaAttr;

    private static Map<String, String> createUserAttr = new HashMap<String, String>();
    private static String userContainer = null;

    private static String DBGNAME = "SPIDSpAccountMapper";
    private static com.sun.identity.shared.debug.Debug debug = null;

    private static final String TINSUFF = "TINIT-";
    private static final String VATSUFF = "VATIT-";

    CustomRepoUtil repoUtil = new CustomRepoUtil();
    CustomFederationUtil util = new CustomFederationUtil();

    // private static String PWD_VAL = "NrskdJfx.4";
    private static String PWD_ATTR = "userPassword";
    private static String ENABLE_ATTR = "inetUserStatus";
    private static String IDCARD_ATTR = "idCard";
    private static String SPIDCODE_ATTR = "spidCode";
    private static String DIGITALADDR_ATTR = "digitalAddress";

    // CDM Attributi aggiunti fase 2
    private static String SPID_MAIL_ATTR = "SPIDemail";
    private static String SPID_MOBILE_ATTR = "Spidmobile";
    private static String CDM_SIPO_UPDATE = "cdmSIPOUpdate";

    private final static String SPID_FISCALNUMBER_ATTRNAME = "fiscalNumber";
    private final static String SPID_IVACODE_ATTRNAME = "ivaCode";

    private static String stringUpdateUserAttr = new String();

    /*** Flag per determinare se l'utente stato creato o meno ***/
    /*
     * private static boolean _creato = false;
     * private void flagCreato() { _creato = true; } //imposta creato a true
     * public static boolean creato() { return _creato; } //ritorna il valore del
     * flag
     */
    /*** Flag per determinare se il telefono mobile � stato modificato ***/
    /*
     * private static boolean _mobileChanged = false;
     * private void flagMobileChanged() { _mobileChanged = true; } //imposta
     * mobileChanged a true
     * public static boolean mobileChanged() { return _mobileChanged; } //ritorna il
     * valore del flag
     */
    /*** Flag per determinare se la mail mobile � stata modificata ***/
    /*
     * private static boolean _mailChanged = false;
     * private void flagMailChanged() { _mailChanged = true; } //imposta mailChanged
     * a true
     * public static boolean mailChanged() { return _mailChanged; } //ritorna il
     * valore del flag
     */
    /***
     * Base URL e credenziali dove sono esposti i servizi rest IDM da richiamare
     ***/
    private static String idmRestURL = null;
    private static String idmRestURL_pwd = null;
    private static String idmRestURL_admin = null;
    // Base URL per andare a interrogare il managed dei comuni su IDM -> modifica
    // per toponomastica
    private static String idmRestURLComuni = null;

    /**
     * Default constructor
     */
    public SPIDSpAccountMapper() {
        super();
        if (debug == null) {
            debug = com.sun.identity.shared.debug.Debug.getInstance(DBGNAME);
        }

        // get advanced properties
        String sEnableCreateFlag = SystemProperties.get(GLOBAL_PROP_CREATEUSER_ENABLE);
        if (sEnableCreateFlag == null || sEnableCreateFlag.trim().equals("")) {
            createUserEnable = false;
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_ENABLE + " undefined: use default value FALSE");
        } else {
            createUserEnable = Boolean.parseBoolean(sEnableCreateFlag);
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_ENABLE + " value: " + createUserEnable);
        }

        userContainer = SystemProperties.get(GLOBAL_PROP_CREATEUSER_BASEDN);
        if (userContainer == null || userContainer.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_BASEDN + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_BASEDN + " value: " + userContainer);
        }

        String strAttributeName = SystemProperties.get(GLOBAL_PROP_CREATEUSER_ATTRIBUTE);
        if (strAttributeName == null || strAttributeName.trim().equals("")) {
            createUserAttr = new HashMap<String, String>();
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_ATTRIBUTE + " undefined: NO user Attribute default set");
        } else {
            String[] aAttributesValue = strAttributeName.split(";");
            for (String attr : aAttributesValue) {
                String[] aAttrValue = attr.split("=");
                createUserAttr.put(aAttrValue[0], aAttrValue[1]);
            }
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_ATTRIBUTE + " value: " + createUserAttr);
        }

        /* CDM */
        String sSetCDMAttribute = SystemProperties.get(GLOBAL_PROP_CREATEUSER_SETCDMATTR);
        if (sSetCDMAttribute == null || sSetCDMAttribute.trim().equals("")) {
            setCDMAttribute = false;
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_SETCDMATTR + " undefined: use default value FALSE");
        } else {
            setCDMAttribute = Boolean.parseBoolean(sSetCDMAttribute);
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_SETCDMATTR + " value: " + setCDMAttribute);
        }

        /*
         * se impostato a true aggiorna lo stato utente ad Active ad ogni accesso SPID
         */
        String sUpdateCDMStatus = SystemProperties.get(GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS);
        if (sUpdateCDMStatus == null || sUpdateCDMStatus.trim().equals("")) {
            updateCDMStatus = false;
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS + " undefined: use default value FALSE");
        } else {
            updateCDMStatus = Boolean.parseBoolean(sUpdateCDMStatus);
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS + " value: " + updateCDMStatus);
        }

        /*
         * se impostato a true abilita la logica di aggiornamento utente ad ogni accesso
         * SPID
         */
        String sUpdateCDMUser = SystemProperties.get(GLOBAL_PROP_UPDATEUSER_FLAG);
        if (sUpdateCDMUser == null || sUpdateCDMUser.trim().equals("")) {
            updateCDMUser = false;
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_UPDATEUSER_FLAG + " undefined: use default value FALSE");
        } else {
            updateCDMUser = Boolean.parseBoolean(sUpdateCDMUser);
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_UPDATEUSER_FLAG + " value: " + updateCDMUser);
        }

        searchUserAttr = SystemProperties.get(GLOBAL_PROP_SEARCHUSER_ATTR);
        if (searchUserAttr == null || searchUserAttr.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_SEARCHUSER_ATTR + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_SEARCHUSER_ATTR + " value: " + searchUserAttr);
        }

        searchPivaAttr = SystemProperties.get(GLOBAL_PROP_SEARCHPIVA_ATTR);
        if (searchPivaAttr == null || searchPivaAttr.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_SEARCHPIVA_ATTR + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_SEARCHPIVA_ATTR + " value: " + searchPivaAttr);
        }

        createUserWs = SystemProperties.get(GLOBAL_PROP_CREATEUSER_WS);
        if (createUserWs == null || createUserWs.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_WS + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEUSER_WS + " value: " + createUserWs);
        }

        /*** IDM ***/
        idmRestURL = SystemProperties.get(GLOBAL_PROP_CREATEIDMUSER_WS);
        if (idmRestURL == null || idmRestURL.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEIDMUSER_WS + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEIDMUSER_WS + " value: " + idmRestURL);
        }

        idmRestURL_admin = SystemProperties.get(GLOBAL_PROP_IDMWS_USER);
        if (idmRestURL_admin == null || idmRestURL_admin.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_IDMWS_USER + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_IDMWS_USER + " value: " + idmRestURL_admin);
        }

        idmRestURL_pwd = SystemProperties.get(GLOBAL_PROP_IDMWS_PWD);
        if (idmRestURL_pwd == null || idmRestURL_pwd.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_IDMWS_PWD + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_IDMWS_PWD + " value: " + idmRestURL_pwd);
        }

        // Aggiunta l'inizializzazione della variabile per la chiamata al managed comuni
        // su IDM -> modifica per toponomastica
        idmRestURLComuni = SystemProperties.get(GLOBAL_PROP_CREATEIDMUSER_WS_COMUNI);
        if (idmRestURLComuni == null || idmRestURLComuni.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEIDMUSER_WS_COMUNI + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_CREATEIDMUSER_WS_COMUNI + " value: " + idmRestURLComuni);
        }

        stringUpdateUserAttr = SystemProperties.get(GLOBAL_PROP_UPDATEUSER_ATTRIBUTE);
        if (stringUpdateUserAttr == null || stringUpdateUserAttr.trim().equals("")) {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_UPDATEUSER_ATTRIBUTE + " undefined.");
        } else {
            if (debug.messageEnabled())
                debug.message(GLOBAL_PROP_UPDATEUSER_ATTRIBUTE + " value: " + stringUpdateUserAttr);
        }
    }

    private void debugAdvancedPropertyVal() {
        String method = "[debugAdvancedPropertyVal]:: ";

        if (debug.messageEnabled()) {
            debug.message(method + "VERSIONE: " + JAR_VERSION);

            debug.message(method + GLOBAL_PROP_CREATEUSER_ENABLE + " value: " + createUserEnable);

            if (userContainer == null || userContainer.trim().equals("")) {
                debug.message(GLOBAL_PROP_CREATEUSER_BASEDN + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_CREATEUSER_BASEDN + " value: " + userContainer);
            }

            debug.message(method + GLOBAL_PROP_CREATEUSER_ATTRIBUTE + " value: " + createUserAttr);

            /* CDM */
            debug.message(method + GLOBAL_PROP_CREATEUSER_SETCDMATTR + " value: " + setCDMAttribute);

            /*
             * se impostato a true aggiorna lo stato utente ad Active ad ogni accesso SPID
             */
            debug.message(method + GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS + " value: " + updateCDMStatus);

            /*
             * se impostato a true abilita la logica di aggiornamento utente ad ogni accesso
             * SPID
             */
            debug.message(method + GLOBAL_PROP_UPDATEUSER_FLAG + " value: " + updateCDMUser);

            if (searchUserAttr == null || searchUserAttr.trim().equals("")) {
                debug.message(method + GLOBAL_PROP_SEARCHUSER_ATTR + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_SEARCHUSER_ATTR + " value: " + searchUserAttr);
            }

            if (searchPivaAttr == null || searchPivaAttr.trim().equals("")) {
                debug.message(method + GLOBAL_PROP_SEARCHPIVA_ATTR + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_SEARCHPIVA_ATTR + " value: " + searchPivaAttr);
            }

            if (createUserWs == null || createUserWs.trim().equals("")) {
                debug.message(method + GLOBAL_PROP_CREATEUSER_WS + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_CREATEUSER_WS + " value: " + createUserWs);
            }

            /*** IDM ***/
            if (idmRestURL == null || idmRestURL.trim().equals("")) {
                debug.message(method + GLOBAL_PROP_CREATEIDMUSER_WS + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_CREATEIDMUSER_WS + " value: " + idmRestURL);
            }

            if (idmRestURL_admin == null || idmRestURL_admin.trim().equals("")) {
                debug.message(method + GLOBAL_PROP_IDMWS_USER + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_IDMWS_USER + " value: " + idmRestURL_admin);
            }

            if (idmRestURL_pwd == null || idmRestURL_pwd.trim().equals("")) {
                debug.message(method + GLOBAL_PROP_IDMWS_PWD + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_IDMWS_PWD + " value: " + idmRestURL_pwd);
            }

            if (idmRestURLComuni == null || idmRestURLComuni.trim().equals("")) {
                debug.message(method + GLOBAL_PROP_CREATEIDMUSER_WS_COMUNI + " undefined.");
            } else {
                debug.message(method + GLOBAL_PROP_CREATEIDMUSER_WS_COMUNI + " value: " + idmRestURLComuni);
            }

        }
    }

    public static Map<String, List<String>> getAttributeMap(String hostEntityID, String realm) throws SAML2Exception {
        Map<String, List<String>> attributeMap = getConfigAttributeMap(realm, hostEntityID, SP);
        return attributeMap;
    }

    @SuppressWarnings({ "unused", "unchecked" })
    public String getIdentity(Assertion assertion, String hostEntityID, String realm) throws SAML2Exception {
        String method = "[getIdentity]:: ";

        if (assertion == null) {
            throw new SAML2Exception(bundle.getString("nullAssertion"));
        }

        if (hostEntityID == null) {
            throw new SAML2Exception(bundle.getString("nullHostEntityID"));
        }

        if (realm == null) {
            throw new SAML2Exception(bundle.getString("nullRealm"));
        }

        // stampa a debug tutte le variabili globali impostate
        debugAdvancedPropertyVal();

        // set default value
        // _mailChanged = false;
        // _mobileChanged = false;
        // _creato = false;

        // Map<String, String> map = getAttributeMap(hostEntityID,realm);
        Map<String, List<String>> map = getAttributeMap(hostEntityID, realm);

        // MODIFICA LOG SPID AZIENDE
        // Flag per controllare che l'accesso sia di tipo AZIENDE
        boolean flagCompany = false;

        // MODIFICA LOG EIDAS
        // Flag per controllare che l'accesso sia di tipo EIDAS
        boolean flagEidas = false;

        // for (Map.Entry<String, String> entry : map.entrySet())
        for (Entry<String, List<String>> entry : map.entrySet()) {
            String key = entry.getKey();
            // String value = entry.getValue();
            List<String> value = entry.getValue();

        }

        NameID nameID = util.getNameID(assertion, hostEntityID, realm);

        String status = "";
        String userID = null;
        String sIvaCode = null;

        String format = nameID.getFormat();
        String remoteEntityID = assertion.getIssuer().getValue();
        if (debug.messageEnabled())
            debug.message(method + "assertion.getIssuer().getValue():" + remoteEntityID);

        List<Attribute> attributes = null;
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements != null) {
            for (Iterator<AttributeStatement> attributeStatementsIterator = attributeStatements
                    .iterator(); attributeStatementsIterator.hasNext();) {
                AttributeStatement attributeStatement = attributeStatementsIterator.next();
                // Get Attributes
                attributes = attributeStatement.getAttribute();
            }
        }

        for (Iterator<Attribute> iter = attributes.iterator(); iter.hasNext();) {
            Attribute attribute = iter.next();

            if (debug.messageEnabled()) {
                debug.message(method + " ATTRIBUTO ASSERTION ---> " + attribute.getName());
                debug.message(method + " VALUE ATTRIBUTO ASSERTION ---> " + attribute.getAttributeValueString());
            }

            // MODIFICA LOG EIDAS
            /**
             * Check per verificare se l'utenza è di tipo EIDAS
             */
            if (attribute.getName().equals("spidCode"))
                flagEidas = checkEidas(attribute.getAttributeValueString().get(0).toString());

            // MODIFICA LOG SPID AZIENDE
            /**
             * Check per verificare se l'utenza è di tipo Company
             */
            if (attribute.getName().equals("companyName"))
                flagCompany = checkCompany(attribute);
        }

        // MODIFICA LOG EIDAS
        /**
         * Il flag flagEidas se è a false gestisce la logica SPID CITTADINO/COMPANY
         * Il flag flagEidas se è a true gestisce la logica EIDAS
         */
        if (!flagEidas) {

            // LOGICA CITTADINO/COMPANY
            if (attributes != null) {
                try {
                    String useAutoFed = getAttribute(realm, hostEntityID, SAML2Constants.AUTO_FED_ENABLED);
                    if ((useAutoFed != null) && useAutoFed.equalsIgnoreCase("true")) {
                        String autoFedAttr = getAttribute(realm, hostEntityID, SAML2Constants.AUTO_FED_ATTRIBUTE);
                        if (debug.messageEnabled()) {
                            debug.message(method + " use auto federation autoFedAttr: " + autoFedAttr);
                        }
                        if (autoFedAttr != null) {
                            // substring del CF
                            List<String> autoFedAttrVal = (List<String>) util.getAttributeVal(attributes, autoFedAttr);
                            if (debug.messageEnabled()) {
                                debug.message(method + "autoFedAttrVal: " + autoFedAttrVal);
                            }

                            for (String val : autoFedAttrVal) {

                                if (val != null && val.startsWith(TINSUFF)) {
                                    userID = val.substring(TINSUFF.length());
                                } else
                                    userID = val;
                            }
                        } else {
                            debug.error(method + " attributo di autofederazione NON definito.");
                        }
                    } else if (nameID != null && nameID.getValue() != null) {
                        // check if we need to use value of Name ID as SP user account
                        String useNameID = getAttribute(realm, hostEntityID, SAML2Constants.USE_NAMEID_AS_SP_USERID);
                        if ((useNameID != null) && useNameID.equalsIgnoreCase("true")) {
                            if (debug.messageEnabled()) {
                                debug.message(method + " use NameID value as userID: " + nameID.getValue());
                            }
                            String userName = nameID.getValue().toUpperCase();
                            if (userName != null && userName.startsWith(TINSUFF)) {
                                userID = userName.substring(TINSUFF.length());
                            } else
                                userID = userName;
                        } else {
                            debug.error(method + " useNameID NULL or FALSE useNameID: " + useNameID);
                        }
                    } else {
                        debug.error(method + " caso non gestito! ");
                    }
                } catch (Exception e) {
                    debug.error(method + "Exception: ", e);
                }
            }

            if (userID != null) {
                // get user
                AMIdentity usrIdentity = null;
                List<AMIdentity> users = new ArrayList<AMIdentity>();

                // Commit di prova
                users = repoUtil.getUserStoreIdentity(userID, realm);

                if (users != null && !users.isEmpty()) { // utente esistente
                    // debug.message(method + "_____users.size(): " + users.size());
                    if (users.size() == 1) {
                        // debug.message(method + "assegna l'unico utente trovato!!! ");
                        usrIdentity = users.get(0);
                    } else {
                        SAML2Exception se = new SAML2Exception(
                                "Eccezione per name[" + userID + "] pi� di un utente con lo stesso codice fiscale");
                        throw se;
                    }
                }

                // MODIFICA LOG SPID AZIENDE
                /**
                 * Il flag flagCompany se è a false gestisce la logica SPID Cittadino
                 * Il flag flagCompany se è a true gestisce la logica SPID Aziende
                 */
                if (!flagCompany) {

                    if (debug.messageEnabled())
                        debug.message(method + " GESTISCO CITTADINO");

                    if (usrIdentity != null) {
                        /* CDM */
                        // aggiornare l'utente per update password ed inetuserstatus=Active
                        if (setCDMAttribute) {
                            if (debug.messageEnabled())
                                debug.message(method + "******* INIZIO Update Utente [" + usrIdentity.getName()
                                        + "] setCDMAttribute CDM ********");

                            try {
                                Map<String, List<?>> userAttrMap = new HashMap<String, List<?>>();
                                /***
                                 * aggiunta parametrizzazione per discriminare se aggiornare lo stato utente o
                                 * meno
                                 **/
                                if (updateCDMStatus) {
                                    if (debug.messageEnabled())
                                        debug.message(method + "******* Update Utente [" + usrIdentity.getName()
                                                + "] inetuserstatus=Active ********");
                                    // inetuserstatus=Active
                                    userAttrMap.put(ENABLE_ATTR, Arrays.asList("Active"));
                                }

                                if (stringUpdateUserAttr != null && !stringUpdateUserAttr.trim().equals("")) {
                                    String[] arrayAttributes = stringUpdateUserAttr.split(";");
                                    for (String attr : arrayAttributes) {
                                        String[] arrayValue = attr.split("=");
                                        if (usrIdentity.getAttribute(arrayValue[0]) != null
                                                && !usrIdentity.getAttribute(arrayValue[0]).isEmpty()) {
                                            if (!getAttrFromSet(usrIdentity.getAttribute(arrayValue[0]))
                                                    .equals(arrayValue[1])) {
                                                userAttrMap.put(arrayValue[0], Arrays.asList(arrayValue[1]));
                                                if (debug.messageEnabled())
                                                    debug.message(method + "staticAttrName[" + arrayValue[0]
                                                            + "] staticAttrVal[" + arrayValue[1] + "]");
                                            }
                                        }
                                    }
                                } else {
                                    if (debug.messageEnabled())
                                        debug.message(method + GLOBAL_PROP_UPDATEUSER_ATTRIBUTE
                                                + " undefined: NO user Attribute default set");
                                }

                                // password
                                userAttrMap.put(PWD_ATTR, Arrays.asList(setPassword()));
                                if (debug.messageEnabled())
                                    debug.message(method + "******* FINE Update Utente [" + usrIdentity.getName()
                                            + "] setCDMAttribute CDM ********");

                                if (updateCDMUser) {
                                    // nuova logica di update
                                    try {
                                        userAttrMap = setUpdateUserAttrMap(map, attributes, userID, userAttrMap);
                                    } catch (ParseException e) {
                                        e.printStackTrace();
                                    }
                                    if (!updateSPIDUsers(usrIdentity, userAttrMap, map)) {
                                        debug.error(method + "Errore aggiornamento utente [" + usrIdentity.getName()
                                                + "]: errore chiamata Rest IDM");
                                        SAML2Exception se = new SAML2Exception(
                                                "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                        throw se;
                                    } else {
                                        return userID;
                                    }
                                } else {
                                    // vecchia gestione
                                    if (!repoUtil.updateSpidUsers(usrIdentity, userAttrMap)) {
                                        debug.error(method + "FEDERATION_FAILED_WRITING_ACCOUNT ["
                                                + usrIdentity.getName() + "]: errore scrittura UserStore");
                                        SAML2Exception se = new SAML2Exception(
                                                "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                        throw se;
                                    } else {
                                        return userID;
                                    }
                                }
                            } catch (SSOException | IdRepoException e) {
                                debug.error(method, e.getLocalizedMessage());
                                debug.error(method + "FEDERATION_FAILED_WRITING_ACCOUNT [" + usrIdentity.getName()
                                        + "]: errore scrittura UserStore");
                                SAML2Exception se = new SAML2Exception(
                                        "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                throw se;
                            }
                        } else {
                            // se l'utente esiste ritorna l'accountID
                            if (debug.messageEnabled()) {
                                debug.message(method + "Utente [" + usrIdentity.getName()
                                        + "] aggiornato - Federazione completata");
                            }
                        }

                        return usrIdentity.getName();
                    } else if (createUserEnable) {
                        // CREA L'UTENTE SPID SULLO USER STORE
                        if (debug.messageEnabled()) {
                            debug.message(method + "L'utente " + userID + " non risulta censito a sistema");
                            debug.message(method + "attributes [" + attributes + " ]");
                        }

                        if (createUserWs != null) {
                            /** richiama un WS di creazione utenza che si occupa anche dello UserStore **/
                            // TODO
                        } else {
                            /** crea l'utente sullo UserStore **/
                            Map<String, List<?>> attributeMap;
                            // ******* crea l'utente sullo userStore ********
                            try {
                                attributeMap = setUserAttrMap(map, attributes, userID);
                                if (!repoUtil.addSpidUsers(userID, realm, null, userContainer, attributeMap)) {
                                    debug.error(method + " utente [" + userID
                                            + "] FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                    SAML2Exception se = new SAML2Exception(
                                            "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                    throw se;
                                } else {
                                    // imposta il flag ad indicare che l'utenza � stata creata
                                    // flagCreato();
                                    debug.message(method + "Utente [" + userID + "] creato - Federazione completata");
                                    return userID;
                                }
                            } catch (SSOException | IdRepoException | ParseException e) {
                                debug.error(method, e.getLocalizedMessage());
                                debug.error(method + " utente [" + userID
                                        + "] FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                SAML2Exception se = new SAML2Exception(
                                        "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                throw se;
                            }
                        }
                    }
                }
                // MODIIFCA LOG SPID AZIENDE
                else {
                    if (debug.messageEnabled())
                        debug.message(method + " GESTISCO COMPANY");
                    SPIDAziendeSpAccountMapper company = new SPIDAziendeSpAccountMapper();
                    return company.getIdentity(assertion, hostEntityID, realm);
                }
            }
        }
        // MODIFICA LOG EIDAS
        else {
            if (debug.messageEnabled())
                debug.message(method + " GESTISCO EIDAS");
            SPIDEidasSpAccountMapper eidas = new SPIDEidasSpAccountMapper();
            return eidas.getIdentity(assertion, hostEntityID, realm);
        }

        return null;

    }

    private Map<String, List<?>> setUserAttrMap(Map<String, List<String>> attributeMap, List<Attribute> attributes,
            String userID) throws ParseException {
        String method = "[setUserAttrMap]";
        if (debug.messageEnabled())
            debug.message(method + "inizio ... ");

        Map<String, List<?>> userAttrMap = new HashMap<String, List<?>>();

        if (debug.messageEnabled())
            debug.message(method + "******* INIZIO Iterator User [" + userID + "] - Attributi Asserzione ********");
        for (Iterator<Attribute> iter = attributes.iterator(); iter.hasNext();) {
            Attribute attribute = iter.next();
            // DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            if (attribute.getName() != null && attribute.getAttributeValueString() != null) {
                // MODIFICA AGGIUNTA PER GESTIONE IDP POSTE - INIZIO
                if (getAttrAssertion(attribute.getAttributeValueString()) != null &&
                        !getAttrAssertion(attribute.getAttributeValueString()).equals("-")) {
                    // MODIFICA AGGIUNTA PER GESTIONE IDP POSTE - FINE
                    if (attribute.getName().equalsIgnoreCase("fiscalNumber")
                            && attribute.getAttributeValueString() != null) {
                        String codfisc = getAttrAssertion(attribute.getAttributeValueString());
                        if (codfisc != null && codfisc.length() >= TINSUFF.length()) {
                            userAttrMap.put(getCorrAttrLDAP(attributeMap, "fiscalNumber"),
                                    Arrays.asList(codfisc.substring(TINSUFF.length())));
                            if (debug.messageEnabled())
                                debug.message(method + "Attr Assertion MAP - fiscalNumber: "
                                        + codfisc.substring(TINSUFF.length()));
                        }
                        /*
                         * } else if (attribute.getName().equalsIgnoreCase("name") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("familyName") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("spidCode") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("gender") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("email") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("mobilePhone") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("placeOfBirth") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("digitalAddress") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("companyName") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("idCard") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("address") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("registeredOffice") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("dateOfBirth") &&
                         * attribute.getAttributeValueString() != null){
                         * if (debug.messageEnabled())
                         * debug.message(method + " -- (dataNascDate): " +
                         * attribute.getAttributeValueString() );
                         * Date dataNascDate =
                         * dateFormat.parse(getAttrAssertion(attribute.getAttributeValueString()));
                         * if (debug.messageEnabled())
                         * debug.message(method + " -- (dataNascDate): " + dataNascDate );
                         * String pattern = "yyyyMMdd000000";
                         * SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
                         * if (debug.messageEnabled())
                         * debug.message(method + "simpleDateFormat.format(dataNascDate): " +
                         * simpleDateFormat.format(dataNascDate));
                         * userAttrMap.put(getCorrAttrLDAP(attributeMap, attribute.getName()),
                         * Arrays.asList( simpleDateFormat.format(dataNascDate) ));
                         */
                    } else if (attribute.getName().equalsIgnoreCase(SPID_IVACODE_ATTRNAME)
                            && attribute.getAttributeValueString() != null) {
                        // utentePortaleSpid.setIvaCode(getAttrAssertion(attribute.getAttributeValueString()));
                        // Per gestire "VATIT-partitaiva"
                        String ivaCode = getAttrAssertion(attribute.getAttributeValueString());
                        if (ivaCode != null && ivaCode.length() >= VATSUFF.length())
                            userAttrMap.put(getCorrAttrLDAP(attributeMap, attribute.getName()),
                                    Arrays.asList(ivaCode.substring(VATSUFF.length())));
                    } else {
                        // userAttrMap.put( getCorrAttrLDAP(attributeMap, attribute.getName()),
                        // Arrays.asList( attribute.getAttributeValueString()) );
                        List<String> lAttrLDAP = getAllCorrAttrLDAP(attributeMap, attribute.getName());
                        // String attrLDAP = getCorrAttrLDAP(attributeMap, attribute.getName());
                        String attrLDAPVal = getAttrAssertion(attribute.getAttributeValueString());
                        for (String attrLDAP : lAttrLDAP) {
                            if (debug.messageEnabled())
                                debug.message(
                                        method + "Generic Attr Assertion MAP - " + attrLDAP + " : " + attrLDAPVal);
                            userAttrMap.put(attrLDAP, Arrays.asList(attrLDAPVal));
                        }
                    }
                } // MODIFICA AGGIUNTA PER GESTIONE IDP POSTE
            }
        }
        if (debug.messageEnabled())
            debug.message(method + "******* FINE Iterator User [" + userID + "] - Attributi Asserzione ********");

        /* CDM */
        if (setCDMAttribute) {
            if (debug.messageEnabled())
                debug.message(method + "******* INIZIO setCDMAttribute User [" + userID + "] - Attributi CDM ********");
            // CN
            if (userAttrMap.get("cn") != null)
                userAttrMap.remove("cn");
            String sNome = getAttrAssertion(util.getAttributeVal(attributes, "name"));
            String sCognome = getAttrAssertion(util.getAttributeVal(attributes, "familyName"));
            userAttrMap.put("cn", Arrays.asList(sNome + " " + sCognome));

            // persona Giuridica o Fisica
            String ivaCode = getAttrAssertion(util.getAttributeVal(attributes, SPID_IVACODE_ATTRNAME));
            if (ivaCode != null && !ivaCode.isEmpty() && !ivaCode.equalsIgnoreCase("-")) {
                userAttrMap.put(SPID_CDM_GIURIDICA_FISICA, Arrays.asList("G"));
            } else {
                userAttrMap.put(SPID_CDM_GIURIDICA_FISICA, Arrays.asList("F"));
            }

            // Gestione address
            if (getAttrAssertion(util.getAttributeVal(attributes, "address")) != null) {
                try {
                    String sAddress = getAttrAssertion(util.getAttributeVal(attributes, "address"));
                    Map<String, String> mAddress = getAddressElement(sAddress);
                    if (mAddress != null && mAddress.size() > 0) {
                        if (userAttrMap.get("street") != null)
                            userAttrMap.remove("street");
                        if (mAddress.get("default") != null) {
                            userAttrMap.put("street", Arrays.asList(mAddress.get("default")));
                        } else {
                            userAttrMap.put("postalCode", Arrays.asList(mAddress.get("postalCode")));
                            if (mAddress.get("st") != null) {
                                userAttrMap.put("st", Arrays.asList(mAddress.get("st")));
                            }
                            userAttrMap.put("street", Arrays.asList(mAddress.get("street").toString()));
                        }
                    }

                    /**
                     * Modifica per toponomastica
                     * Aggiunta la gestione del campo l e cdmResidenzaCodiceComune.
                     * Viene successivamente eseguita la chiamata all'API di IDM per ottenere i
                     * valori del mapped dei comuni.
                     * Questo serve perchè se si ha il codiceComune bisogna trovare il nomeComune,
                     * altrimenti viceversa.
                     */
                    String codiceComune = getCodiceComune(sAddress);
                    String nomeComune = getNomeComune(sAddress);
                    Boolean flagInput = false;
                    String input = null;

                    if (codiceComune != null) {
                        userAttrMap.put("cdmResidenzaCodiceComune", Arrays.asList(codiceComune));
                        input = codiceComune;
                        flagInput = false;

                    }

                    if (nomeComune != null) {
                        userAttrMap.put("l", Arrays.asList(nomeComune));
                        input = nomeComune;
                        flagInput = true;
                    }

                    try {
                        /*
                         * Chiamata al servizio per restituire i valore del mapped comuni da IDM.
                         * Se il flagInput è true allora gestisce la casistica di ricerca per trovare il
                         * codiceComune,
                         * altrimenti gestisce la casistica per trovare il nomeComune.
                         * Viene aggiornata la mappa userAttrMap con l'inserimento del valor l o
                         * cdmResidenzaCodiceComune in base alla casistica di ricerca.
                         */
                        sendGETComuni(idmRestURLComuni, idmRestURL_admin, idmRestURL_pwd, flagInput, input,
                                userAttrMap);
                    } catch (Exception e) {
                        debug.error(method + "ERRORE chiamata rest [" + idmRestURLComuni + "]:: " + e.getMessage());
                    }

                    /**
                     * Modifica per toponomastica
                     * Aggiunta la gestione del campo cdmVia e cdmNumeroCivico
                     */
                    Map<String, String> listCdmCivicoVia = getCdmCivicoVia(mAddress.get("street"));
                    if (!listCdmCivicoVia.isEmpty()) {
                        if (listCdmCivicoVia.get("cdmVia") != null) {
                            userAttrMap.put("cdmVia", Arrays.asList(listCdmCivicoVia.get("cdmVia")));
                        }
                        if (listCdmCivicoVia.get("cdmNumeroCivico") != null) {
                            userAttrMap.put("cdmNumeroCivico", Arrays.asList(listCdmCivicoVia.get("cdmNumeroCivico")));
                        }
                    }

                } catch (IndexOutOfBoundsException ex) {
                    debug.error(method, ex.getLocalizedMessage());
                }
            }

            // aggiunto attributo cdmNascitaData
            if (getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")) != null &&
                    !getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")).isEmpty()) {
                DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
                String sdataNascDate = getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth"));
                if (debug.messageEnabled())
                    debug.message(method + " -- (sdataNascDate): " + sdataNascDate);
                Date dataNascDate = dateFormat.parse(sdataNascDate);

                // cdmNascitaDataOld
                userAttrMap.put("cdmNascitaDataOld",
                        Arrays.asList(new SimpleDateFormat("yyyy-MM-dd").format(dataNascDate)));

                // cdmNascitaData
                userAttrMap.put("cdmNascitaData",
                        Arrays.asList(new SimpleDateFormat("yyyyMMdd000000").format(dataNascDate)));
            }

            // TODO updateCDMUser
            // aggiunto attributo SpidMail
            if (getAttrAssertion(util.getAttributeVal(attributes, "email")) != null &&
                    !getAttrAssertion(util.getAttributeVal(attributes, "email")).isEmpty()) {
                String sSpidEmail = getAttrAssertion(util.getAttributeVal(attributes, "email"));
                if (debug.messageEnabled())
                    debug.message(method + " -- (" + SPID_MAIL_ATTR + "): " + sSpidEmail);

                userAttrMap.put(SPID_MAIL_ATTR, Arrays.asList(sSpidEmail));
            }

            // aggiunto attributo SpidMobile
            if (getAttrAssertion(util.getAttributeVal(attributes, "mobilePhone")) != null &&
                    !getAttrAssertion(util.getAttributeVal(attributes, "mobilePhone")).isEmpty()) {
                String sSpidMobile = getAttrAssertion(util.getAttributeVal(attributes, "mobilePhone"));
                if (debug.messageEnabled())
                    debug.message(method + " -- (" + SPID_MOBILE_ATTR + "): " + sSpidMobile);

                userAttrMap.put(SPID_MOBILE_ATTR, Arrays.asList(sSpidMobile));
            }

            userAttrMap.put(PWD_ATTR, Arrays.asList(setPassword()));
            if (debug.messageEnabled())
                debug.message(method + "******* FINE setCDMAttribute User [" + userID + "] - Attributi CDM ********");
        }

        if (createUserAttr != null && !createUserAttr.isEmpty()) {
            if (debug.messageEnabled())
                debug.message(
                        method + "******* INIZIO setCDMAttribute User [" + userID + "] - Attributi Statici ********");
            // se esistono attributi di default li imposta
            for (Map.Entry<String, String> entry : createUserAttr.entrySet()) {
                String defaultAttr = entry.getKey();
                String defaultAttrVal = entry.getValue();
                if (debug.messageEnabled())
                    debug.message(method + "defaultAttr[" + defaultAttr + "] defaultAttrVal[" + defaultAttrVal + "]");
                userAttrMap.put(defaultAttr, Arrays.asList(defaultAttrVal));
            }
            if (debug.messageEnabled())
                debug.message(
                        method + "******* FINE setCDMAttribute User [" + userID + "] - Attributi Statici ********");
        }

        return userAttrMap;
    }

    /*
     * Utility per split dell'indirizzo da Asserzione
     * sElement: elemento da recuperare
     * return Map: mapper con gli elementi splittati,
     * Key: postalCode - codice postale
     * Key: street - indirizzo
     * Key: st - provincia
     * Key: default - se non possibile ritorna address con il valore originale
     * dell'asserzione
     */
    private static Map<String, String> getAddressElement(String sAddress) {
        String method = "[getAddressElement]::";
        if (debug.messageEnabled())
            debug.message(method + "--------  Address: " + sAddress + " ------------");
        Map<String, String> mAddress = new ArrayMap<>();
        if (sAddress != null && !sAddress.isEmpty() && !sAddress.equalsIgnoreCase("null")) {

            try {
                String sSplitAddress = sAddress.replace("/", "");
                // String sAppoStreet = sAddress;

                // aggiunta gestione senza numero civico
                if (getFirstNumber(sSplitAddress) != null) {
                    // String sNumeroCivico = getFirstNumber(sSplitAddress);
                    // int indice = sSplitAddress.indexOf(sNumeroCivico) + sNumeroCivico.length();
                    // String appo = sSplitAddress.substring(indice);

                    // aggiunta gestione senza numero civico
                    // String postalCode = getFirstNumber(appo);
                    if (getPostalCode(sSplitAddress) != null) {
                        String postalCode = getPostalCode(sSplitAddress);
                        mAddress.put("postalCode", postalCode);

                        String sStreet = getStreetAddress(sAddress, postalCode);
                        mAddress.put("street", sStreet);

                        /*
                         * Vecchia gestione del campo st perchè il provider "" non stampa la provincia.
                         * E' stato creato il metodo getProvince() per recuperare correttamente la
                         * provincia.
                         */
                        // String sSt = sSplitAddress.substring(sSplitAddress.length() - 2);
                        String[] sSplitAddressArray = sSplitAddress.replace(sStreet, "").replace(postalCode, "")
                                .split(" ");
                        String sSt = null;
                        if (getProvince(sSplitAddressArray) != null) {
                            sSt = getProvince(sSplitAddressArray);
                            mAddress.put("st", sSt);
                        }

                        if (debug.messageEnabled()) {
                            debug.message(method + "st[" + sSt + "]");
                            debug.message(method + "postalCode[" + postalCode + "]");
                            debug.message(method + "street[" + sStreet + "]");
                        }
                        return mAddress;
                    }
                }
            } catch (IndexOutOfBoundsException ex) {
                debug.error(method + ex.getLocalizedMessage());
            }
        }
        mAddress.put("default", sAddress); // se non si riesce a prasare ritorna la stringa originale
        return mAddress;
    }

    /*
     * Utility per impostazione password
     */
    private String setPassword() {
        String method = "[setPassword]::";
        // imposta la password
        String randomPwd = "";
        String[] chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
        for (int alpha = 4; alpha > 0; alpha--) {
            double randNumbAlpha = Math.random();
            randNumbAlpha = randNumbAlpha * (chars.length - 10);
            Double charIndexAlpha = Math.floor(randNumbAlpha) + 10;
            randomPwd = randomPwd + chars[charIndexAlpha.intValue()];
        }
        double randNumbDigit = Math.random();
        randNumbDigit = randNumbDigit * 10;
        double charIndexDigit = Math.floor(randNumbDigit);
        randomPwd = randomPwd + chars[(int) charIndexDigit];
        for (int i = 12; i > 0; --i) {
            double randNumb = Math.random();
            randNumb = randNumb * chars.length;
            Double charIndex = Math.floor(randNumb);
            if (randomPwd.indexOf(chars[charIndex.intValue()]) < 0) {
                randomPwd = randomPwd + chars[charIndex.intValue()];
            }
        }

        return randomPwd;
    }

    /**
     * @param spidCode, valore preso dalla SAML Responde
     * @return se lo spidCode fa match con la regular expression ritorna true
     *         (quindi è accesso con eidas)
     */
    private static Boolean checkEidas(String spidCode) {
        String method = "[checkEidas]::";

        // Regular Expression
        String regularExpression = "[A-Z]{2}/[A-Z]{2}/\\d{9,14}";

        // Oggetto per impostare quale regularExpression utilizzare e con quale stringa
        // si vuole fare il confronto
        Pattern pattern = Pattern.compile(regularExpression);
        Matcher matcher = pattern.matcher(spidCode);

        // Con l'oggetto matcher si possono utilizzare tutti i metodi di match
        // Se la condizione viene superata, si tratta di accesso EIDAS e il flag viene
        // portato a true
        if (matcher.matches()) {
            if (debug.messageEnabled())
                debug.message(method + "è un'utenza eidas");
            return true;
        }

        return false;
    }

    /**
     * @param attribute, parametro della SAML Request
     * @returns se il campo companyName è popolato allora si tratta di un accesso
     *          SPID AZIENDE e il flag viene messo a true(accesso SPID COMPANY)
     */
    private static Boolean checkCompany(Attribute attribute) {
        String method = "[checkCompany]::";

        // Ciclo tutti i campi dell'attributo e controllo se è vuoto o popolato
        // Se fosse vuoto, sostituisco il carattere "-" per rendere il campo pulito
        for (int i = 0; i < attribute.getAttributeValueString().size(); i++) {

            String value = attribute.getAttributeValueString().get(i).toString();
            String valueNew = value.replaceAll("-", "");

            if (!valueNew.isEmpty()) {
                if (debug.messageEnabled())
                    debug.message(method + "è un'utenza company");
                return true;
            }
        }
        //
        // for (String value : attribute.getAttributeValueString()) {
        //
        // String valueNew = value.replaceAll("-", "");
        //
        // if (!valueNew.isEmpty())
        // return true;
        // }
        return false;
    }

    private static String getFirstNumber(String stringa) {
        Matcher m = Pattern.compile("[^0-9]*([0-9]+).*").matcher(stringa);
        if (m.matches()) {
            return m.group(1);
        }
        return null;
    }

    private static String getPostalCode(String stringa) {
        Matcher m = Pattern.compile("[0-9]{5}").matcher(stringa);
        while (m.find()) {
            return m.group().toString();
        }
        return null;
    }

    private static String getProvince(String[] arrayStringa) {
        for (String parola : arrayStringa) {
            Matcher m = Pattern.compile("^[A-Z]{2}$").matcher(parola);
            if (m.matches()) {
                return m.group();
            }
        }

        return null;
    }

    private static String getStreetAddress(String stringa, String postalCode) {
        int indice = stringa.indexOf(postalCode);
        if (indice > 0 && indice < stringa.length()) {
            String sStreet = stringa.substring(0, indice);
            return sStreet.trim();
        } else
            return stringa;
    }

    /**
     * Metodo che splitta il campo "street" per ottenere il campo cdmNumeroCivico e
     * cdmVia.
     * Lo split viene eseguito attraverso l'utilizzo dell'esspressione che accetta o
     * una sequenza di numero o una sequenza di non numeri.
     * Viene costruita una mappa con la key "cdmNumeroCivico" e "cdmVia"
     *
     * @param street campo street da splittare
     * @return mappa con la key "cdmCivico e "cdmVia"
     */
    private static Map<String, String> getCdmCivicoVia(String street) {
        String method = "[getCdmCivicoVia::]";
        if (debug.messageEnabled())
            debug.message(method + "gestione del campo street per ottenere il campo cdmNumeroCivico e cdmVia...");

        Map<String, String> listFields = new HashMap<>();

        // Regex migliorata per separare via e numero civico
        Pattern pattern = Pattern.compile("^(.*?)[,\\s]*([0-9]+\\s*[a-zA-Z/\\-]*)$");
        Matcher matcher = pattern.matcher(street.trim());

        if (matcher.find()) {
            String via = matcher.group(1).trim();
            String numeroCivico = matcher.group(2).trim();

            listFields.put("cdmVia", via);
            listFields.put("cdmNumeroCivico", numeroCivico);

            if (debug.messageEnabled()) {
                debug.message(method + "[cdmVia] = [" + via + "]");
                debug.message(method + "[cdmNumeroCivico] = [" + numeroCivico + "]");
            }
        } else {
            // Se non trova il numero, considera tutta la stringa come via
            listFields.put("cdmVia", street.trim());
            if (debug.messageEnabled())
                debug.message(method + "[cdmVia] = [" + street.trim() + "]");
        }

        return listFields;
    }

    /**
     * Metodo che recupera dall'address il codice del comune.
     * 
     * @param address Valore address che arriva dalla SAML
     * @return Il valore del codice del comune
     */
    public String getCodiceComune(String address) {

        String method = "[getCodiceComune]::";

        String codiceComune = "";
        String[] listStringheAddressUno = address.split(" ");

        /**
         * Espressione regolare per identificare un codice catastale italiano.
         * ^[A-Za-z] -> Inizia con una singola lettera (maiuscola o minuscola)
         * [0-9]{3}$ -> Seguita da esattamente tre numeri
         * La regex completa è case-insensitive (Pattern.CASE_INSENSITIVE) per matchare
         * sia 'A' che 'a'.
         */
        String regexCodiceCatastale = "^[A-Za-z][0-9]{3}$";
        Pattern CodiceCatastalePattern = Pattern.compile(regexCodiceCatastale, Pattern.CASE_INSENSITIVE);

        for (String stringa : listStringheAddressUno) {

            // Verifica se l'elemento corrisponde al pattern del codice catastale, con il
            // trim rimuove eventuali spazi bianchi
            Matcher matcher = CodiceCatastalePattern.matcher(stringa.trim());

            if (matcher.find()) {
                // Aggiungi il codice catastale trovato alla lista convertito in maiuscolo
                codiceComune = matcher.group().toUpperCase();

                if (debug.messageEnabled())
                    debug.message(method + "[cdmResidenzaCodiceComune] = [" + codiceComune + "]");

                return codiceComune;
            }
        }

        return codiceComune;
    }

    /**
     * Metodo che recupera dall'address il nome del comune.
     * 
     * @param address Valore address che arriva dalla SAML
     * @return Il valore del nome del comune
     */
    public String getNomeComune(String address) {

        String method = "[getNomeComune]::";

        String nomeComune = null;

        /**
         * Espressione regolare per catturare CAP, Comune e Provincia dalla fine di una
         * stringa di indirizzo.
         *
         * Spiegazione della Regex:
         * (\\d{5}) -> Primo gruppo di cattura: 5 cifre consecutive (il CAP).
         * \\s+ -> Uno o più spazi bianchi.
         * ([A-Za-zÀ-ÖØ-öø-ÿ\\s'-]+?) -> Secondo gruppo di cattura: il nome del Comune.
         * [A-Za-zÀ-ÖØ-öø-ÿ] -> Corrisponde a lettere (maiuscole/minuscole, incluse
         * accentate italiane).
         * \\s'- -> Include spazi, apostrofi e trattini (per nomi come "Sesto San
         * Giovanni", "Sant'Angelo", "Castel Maggiore").
         * +? -> Uno o più occorrenze, in modalità "non avida" (lazy), per fermarsi
         * prima del prossimo delimitatore.
         * \\s+ -> Uno o più spazi bianchi.
         * ([A-Z]{2}) -> Terzo gruppo di cattura: 2 lettere maiuscole (la sigla della
         * Provincia); per renderla opzionale, la racchiudiamo in un gruppo non di
         * cattura (?:...) e aggiungiamo un quantificatore ? (zero o una * occorrenza).
         * $ -> Assicura che la corrispondenza avvenga alla fine della stringa.
         */
        String regexNonCodiceCatastaleNonProvincia = "(\\d{5})\\s+([A-Za-zÀ-ÖØ-öø-ÿ\\s'-]+?)(?:\\s+([A-Z]{2}))?$";
        Pattern NonCodiceCatastalePattern = Pattern.compile(regexNonCodiceCatastaleNonProvincia);

        Matcher matcher = NonCodiceCatastalePattern.matcher(address);
        if (matcher.find()) {

            nomeComune = matcher.group(2);

            if (debug.messageEnabled())
                debug.message(method + "[l] = [" + nomeComune + "]");

            return nomeComune;
        }

        return nomeComune;

    }

    /*
     * Partendo dal nome dell'attributo dell'asserzione recupera l'attributo ldap
     * corrispondente
     */
    private String getCorrAttrLDAP(Map<String, List<String>> attributeMap, String assertionAttrName) {
        String method = "[getCorrAttrLDAP]";
        // mappa gli attributi LDAP con quelli dell'asserzione
        for (Entry<String, List<String>> entry : attributeMap.entrySet()) {
            String assertionAttr = entry.getKey();
            List<String> luserAttr = entry.getValue();

            // if(debug.messageEnabled()){
            // debug.message(method + "assertionAttr: " + assertionAttr );
            // debug.message(method + "luserAttr: " + luserAttr );
            // }

            if (assertionAttr.equalsIgnoreCase(assertionAttrName)) {
                for (String userAttr : luserAttr) {
                    return userAttr;
                }
            }
        }
        return null;
    }

    /*
     * Partendo dal nome dell'attributo dell'asserzione recupera l'attributo ldap
     * corrispondente
     */
    private List<String> getAllCorrAttrLDAP(Map<String, List<String>> attributeMap, String assertionAttrName) {
        String method = "[getAllCorrAttrLDAP]";
        // mappa gli attributi LDAP con quelli dell'asserzione
        for (Entry<String, List<String>> entry : attributeMap.entrySet()) {
            String assertionAttr = entry.getKey();
            List<String> luserAttr = entry.getValue();

            if (debug.messageEnabled()) {
                debug.message(method + "assertionAttr: " + assertionAttr);
                debug.message(method + "luserAttr: " + luserAttr);
            }

            if (assertionAttr.equalsIgnoreCase(assertionAttrName)) {
                return luserAttr;
            }
        }
        return null;
    }

    @SuppressWarnings({ "unused" })
    private String getUserFromAssertion(List<Attribute> attrMapAssertion) {
        String method = "[getUserFromAssertion]";
        for (Iterator<Attribute> iter = attrMapAssertion.iterator(); iter.hasNext();) {
            Attribute attribute = iter.next();
            if (attribute.getName() != null && attribute.getAttributeValueString() != null) {

                if (attribute.getName().equalsIgnoreCase("fiscalNumber")
                        && attribute.getAttributeValueString() != null) {
                    String codfisc = getAttrAssertion(attribute.getAttributeValueString());
                    if (codfisc != null && codfisc.length() >= TINSUFF.length()) {
                        // debug.message(method + "[" + attribute.getName() + "]["+
                        // getAttrAssertion(attribute.getAttributeValueString()) + "]");
                        return codfisc.substring(TINSUFF.length());
                    }

                }
            }
        }
        return null;
    }

    private String getAttrAssertion(List<?> values) {
        if (values == null || values.size() == 0) {
            return null;
        } else {
            return (String) values.get(0);
        }
    }

    private String getAttrFromSet(Set<String> value) {
        String valueStr = null;
        if (value != null && value.size() > 0) {
            for (String val : value) {
                valueStr = val.toString();
            }

        }
        return valueStr;
    }

    /**
     * Checks if dynamical profile creation or ignore profile is enabled.
     *
     * @param realm realm to check the dynamical profile creation attributes.
     * @return true if dynamical profile creation or ignore profile is enabled,
     *         false otherwise.
     */
    protected boolean isDynamicalOrIgnoredProfile(String realm) {

        return SAML2PluginsUtils.isDynamicalOrIgnoredProfile(realm);
    }

    /**
     * Returns the attribute map by parsing the configured map in hosted
     * provider configuration
     *
     * @param realm        realm name.
     * @param hostEntityID <code>EntityID</code> of the hosted provider.
     * @return a map of local attributes configuration map.
     *         This map will have a key as the SAML attribute name and the value
     *         is the local attribute.
     * @throws <code>SAML2Exception</code> if any failured.
     */
    public static Map<String, List<String>> getConfigAttributeMap(String realm, String hostEntityID,
            String role) throws SAML2Exception {
        String method = "[getConfigAttributeMap]:: ";

        if (realm == null) {
            debug.error(method + "nullRealm");
            return null;
        }

        if (hostEntityID == null) {
            debug.error(method + "nullHostEntityID");
            return null;
        }

        SAML2MetaManager saml2MetaManager = SAML2Utils.getSAML2MetaManager();

        if (debug.messageEnabled()) {
            debug.message(method + " DefaultAttrMapper: realm=" + realm + ", entity id=" +
                    hostEntityID + ", role=" + role);
        }
        try {
            Map<?, ?> attribConfig = null;
            IDPSSOConfigElement IDPSSOconfig = null;
            SPSSOConfigElement SPSSOconfig = null;
            if (role.equals(SAML2Constants.SP_ROLE)) {
                SPSSOconfig = saml2MetaManager.getSPSSOConfig(realm, hostEntityID);
                if (SPSSOconfig == null) {
                    if (debug.warningEnabled()) {
                        debug.warning(method + "configuration is not defined.");
                    }
                    return Collections.emptyMap();
                }
                attribConfig = SAML2MetaUtils.getAttributes(SPSSOconfig);
            } else if (role.equals(SAML2Constants.IDP_ROLE)) {
                IDPSSOconfig = saml2MetaManager.getIDPSSOConfig(realm, hostEntityID);
                if (IDPSSOconfig == null) {
                    if (debug.warningEnabled()) {
                        debug.warning(method + "configuration is not defined.");
                    }
                    return Collections.emptyMap();
                }
                attribConfig = SAML2MetaUtils.getAttributes(IDPSSOconfig);
            }

            List<?> mappedAttributes = (List<?>) attribConfig.get(SAML2Constants.ATTRIBUTE_MAP);

            if ((mappedAttributes == null) || (mappedAttributes.size() == 0)) {
                if (debug.messageEnabled()) {
                    debug.message(method +
                            "Attribute map is not defined for entity: " +
                            hostEntityID);
                }
                return Collections.emptyMap();
            }
            Map<String, List<String>> map = new HashMap<String, List<String>>();

            for (Iterator<?> iter = mappedAttributes.iterator(); iter.hasNext();) {
                String entry = (String) iter.next();

                if (entry.indexOf("=") == -1) {
                    if (debug.messageEnabled()) {
                        debug.message(method + "Invalid entry." + entry);
                    }
                    continue;
                }

                StringTokenizer st = new StringTokenizer(entry, "=");
                String key = st.nextToken();
                String value = st.nextToken();
                if (map != null && map.containsKey(key) && map.get(key) != null) {
                    List<String> lvalue = new ArrayList<String>(map.get(key));
                    lvalue.add(value);
                    map.put(key, lvalue);
                } else {
                    map.put(key, Arrays.asList(value));
                }
            }

            return map;

        } catch (SAML2MetaException sme) {
            debug.error(method, sme);
            throw new SAML2Exception(sme.getMessage());
        }
    }

    /**
     * NOTA: In caso di aggiunta di un attributo LDAP da modificare ricordarsi di
     * aggiungere il mapping IDM
     *
     * @param usrIdentity
     * @param attributeMap Attributi da aggiornare
     * @return boolean true aggiornamento riuscito false errore
     * @throws IdRepoException
     * @throws SSOException
     */
    private boolean updateSPIDUsers(AMIdentity usrIdentity, Map<String, List<?>> attributeMap,
            Map<String, List<String>> attributeSPIDMap)
            throws IdRepoException, SSOException {
        String method = "[updateSPIDUsers]:: ";
        if (debug.messageEnabled()) {
            debug.message(method + "parametri: usrIdentity[" + usrIdentity + "]");
            debug.message(method + "attributeMap [" + attributeMap + " ]");
        }

        try {
            // aggiorna l'utente
            if (debug.messageEnabled())
                debug.message(method + "inizio update utente SPID [" + usrIdentity.getName() + "]... ");

            String sDefaultEmail = getCorrAttrLDAP(attributeSPIDMap, "email");
            String sDefaultMobile = getCorrAttrLDAP(attributeSPIDMap, "mobilePhone");
            String sActualValueEmail = null;
            String sActualValueMobile = null;

            if (attributeMap != null && !attributeMap.isEmpty()) {
                Map<String, Set<String>> attrs = new HashMap<String, Set<String>>();
                Set<String> vals = new HashSet<String>();
                /*
                 * modifica del default da false a true - quindi non va aggiornato solo nel caso
                 * in cui il sipoupdate � a true
                 */
                /*
                 * Modifica fatta per la gestione della toponomastica.
                 * Attiva la casistica dell'update sul campo solo address.
                 * La casistica è gestita dal flag updateAddress = true.
                 */
                // boolean updateAddress = false;
                boolean updateAddress = true;
                boolean updateIDMUser = false;

                if (usrIdentity.getAttribute(CDM_SIPO_UPDATE) != null) {
                    Set<String> actualAttrVal = usrIdentity.getAttribute(CDM_SIPO_UPDATE);
                    for (String valore : actualAttrVal) {
                        // if( valore.equalsIgnoreCase("false") ) {
                        // updateAddress = true;
                        // }
                        if (valore.equalsIgnoreCase("true")) {
                            updateAddress = false;
                        }
                    }
                }

                // prende l'attuale valore dell'email censito
                if (usrIdentity.getAttribute(sDefaultEmail) != null) {
                    Set<String> actualAttrVal = usrIdentity.getAttribute(sDefaultEmail);
                    for (String valore : actualAttrVal) {
                        sActualValueEmail = valore;
                    }
                }

                // prende l'attuale valore del mobile censito
                if (usrIdentity.getAttribute(sDefaultMobile) != null) {
                    Set<String> actualAttrVal = usrIdentity.getAttribute(sDefaultMobile);
                    for (String valore : actualAttrVal) {
                        sActualValueMobile = valore;
                    }
                }

                // attributi LDAP da aggiornare con i valori del SAML
                for (Entry<String, List<?>> entry : attributeMap.entrySet()) {
                    // attributo LDAP
                    String userAttr = entry.getKey();
                    // valore attuale dell'attributo LDAP
                    Set<String> actualAttrVal = usrIdentity.getAttribute(userAttr);
                    // valore del SAML da impostare
                    if (entry.getValue() != null) {
                        vals = new HashSet<String>();
                        Object[] userVals = entry.getValue().toArray();
                        String sVals = userVals[0].toString();
                        for (int i = 0; i < userVals.length; i++) {
                            if (userVals[i] != null && !userVals[i].toString().isEmpty())
                                vals.add((String) userVals[i]);
                        }

                        if (userAttr.equalsIgnoreCase("address")) {
                            /* se cdmSIPOUpdated = false -> modificare anche address */
                            if (updateAddress) {
                                if (debug.messageEnabled())
                                    debug.message(method + "updateAddress TRUE");
                                if (actualAttrVal != null && !actualAttrVal.isEmpty()) {
                                    for (String valore : actualAttrVal) {
                                        if (!valore.equals(sVals)) {
                                            updateIDMUser = true;
                                            // se sono diversi imposta l'attributo
                                            attrs.put(userAttr, vals);
                                            if (debug.messageEnabled())
                                                debug.message(method + "userAttr[" + userAttr + "] actualAttrVal: "
                                                        + actualAttrVal.toString()
                                                        + " vals[ " + vals + "]");
                                        }
                                    }
                                } else {
                                    updateIDMUser = true;
                                    // se il valore attuale � null e quello SAML no lo imposta
                                    attrs.put(userAttr, vals);
                                    if (debug.messageEnabled())
                                        debug.message(method + userAttr + ": " + vals);
                                }
                            }
                        } else {
                            // Per attributi diversi da Address ...
                            if (actualAttrVal != null && !actualAttrVal.isEmpty()) { // se il valore attuale
                                                                                     // dell'attributo non � null

                                for (String actualVal : actualAttrVal) {

                                    /*
                                     * In caso di variazione, dovr� essere propagato in HTTP header insieme al
                                     * relativo flag di controllo ( spidmobilechanged )
                                     */
                                    if (userAttr.equalsIgnoreCase(SPID_MOBILE_ATTR)) {
                                        if (sActualValueMobile != null) {
                                            attrs.put(SPID_MOBILE_ATTR, vals);
                                            // if( !actualVal.equalsIgnoreCase(sVals) &&
                                            // !sActualValueMobile.equalsIgnoreCase(sVals) ) {
                                            if (!actualVal.equalsIgnoreCase(sVals)) {
                                                updateIDMUser = true;
                                                if (debug.messageEnabled())
                                                    debug.message(method + " updateIDMUser - sVals: " + sVals
                                                            + " actualAttrVal: " + actualVal);
                                            }
                                        } else {
                                            // se l'attuale mobile dell'utente e null imposta comunque lo
                                            // SPID_MOBILE_ATTR
                                            attrs.put(SPID_MOBILE_ATTR, vals);
                                            if (debug.messageEnabled())
                                                debug.message(method + "set[" + SPID_MOBILE_ATTR
                                                        + "] valore Attributo sActualValueMobile NULL ... ");
                                        }
                                    } else if (userAttr.equalsIgnoreCase(SPID_MAIL_ATTR)) {
                                        // se sono diversi o l'email attuale o la mail SPID imposta l'attributo
                                        // SPID_MOBILE_ATTR ed il relativo flag
                                        attrs.put(SPID_MAIL_ATTR, vals);
                                        if (sActualValueEmail != null) {
                                            // if( !actualVal.equalsIgnoreCase(sVals) &&
                                            // !sActualValueEmail.equalsIgnoreCase(sVals) ) {
                                            if (!actualVal.equals(sVals)) {
                                                updateIDMUser = true;
                                                if (debug.messageEnabled())
                                                    debug.message(method + " updateIDMUser - sVals: " + sVals
                                                            + " actualAttrVal: " + actualVal);
                                            }
                                        } else {
                                            // se l'attuale email dell'utente e null imposta comunque lo SPID_MAIL_ATTR
                                            attrs.put(SPID_MAIL_ATTR, vals);
                                            if (debug.messageEnabled())
                                                debug.message(method + "set[" + SPID_MAIL_ATTR
                                                        + "]  valore Attributo sActualValueEmail NULL ... ");
                                        }
                                    } else {
                                        if (!actualVal.equalsIgnoreCase(sVals)) {
                                            // se sono diversi imposta l'attributo
                                            attrs.put(userAttr, vals);

                                            if (!userAttr.equalsIgnoreCase(PWD_ATTR)
                                                    && !userAttr.equalsIgnoreCase(ENABLE_ATTR)
                                                    && !userAttr.equalsIgnoreCase(IDCARD_ATTR)
                                                    && !userAttr.equalsIgnoreCase(SPIDCODE_ATTR)
                                                    && !userAttr.equalsIgnoreCase(DIGITALADDR_ATTR)) {
                                                updateIDMUser = true;
                                                if (debug.messageEnabled())
                                                    debug.message(method + "userAttr[" + userAttr + "] actualAttrVal: "
                                                            + actualAttrVal.toString()
                                                            + " vals[ " + vals + "]");
                                            }
                                        }
                                    }
                                }
                            } else {
                                if (vals != null && !vals.isEmpty()) {
                                    for (Iterator<String> iter = vals.iterator(); iter.hasNext();) {
                                        String value = iter.next();
                                        if (value != null && !value.isEmpty()) {
                                            if (!userAttr.equalsIgnoreCase(PWD_ATTR)
                                                    && !userAttr.equalsIgnoreCase(ENABLE_ATTR)
                                                    && !userAttr.equalsIgnoreCase(IDCARD_ATTR)
                                                    && !userAttr.equalsIgnoreCase(SPIDCODE_ATTR)
                                                    && !userAttr.equalsIgnoreCase(DIGITALADDR_ATTR)) {
                                                updateIDMUser = true;
                                                // se il valore attuale � null e quello SAML no lo imposta
                                                attrs.put(userAttr, vals);
                                                if (debug.messageEnabled())
                                                    debug.message(method + userAttr + ": " + vals);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // se il valore del SAML � null
                        if (debug.messageEnabled())
                            debug.message(method + " valore Attributo SAML [" + userAttr + "] NULL ... ");
                        if (actualAttrVal != null && !actualAttrVal.isEmpty()) {
                            updateIDMUser = true;
                            // se il valore SAML � null ma l'attuale valore dell'attr non lo � lo svuota
                            attrs.put(userAttr, new HashSet<String>());
                            if (debug.messageEnabled())
                                debug.message(method + userAttr + " set VUOTO! ");
                        }
                    }

                    attrs.remove("street");

                }
                if (attrs != null && !attrs.isEmpty()) {

                    // aggiornamento Identity LDAP
                    usrIdentity.setAttributes(attrs);
                    usrIdentity.store();
                    // TODO verificare se � un solo attributo e se � password o inetUserStatus non
                    // fa la chiamata REST
                    if (idmRestURL != null && !idmRestURL.isEmpty()) {
                        if (updateIDMUser) {
                            // chiamata REST a IDM
                            CustomRestUtil restUtil;
                            try {
                                restUtil = new CustomRestUtil(idmRestURL, idmRestURL_admin, idmRestURL_pwd);
                                if (restUtil.updateIDMUser(usrIdentity.getName(), attrs))
                                    debug.message(method + " OK Chiamata REST IDM user[" + usrIdentity.getName()
                                            + "] Aggiornato");
                                else {
                                    debug.error(method + "ERRORE chiamata rest [" + idmRestURL + "]  IDM user["
                                            + usrIdentity.getName() + "]");
                                    // return false; //si � scelto di non interrompere l'accesso in caso di
                                    // eccezioni o errori nella chiamata REST
                                }
                            } catch (Exception e) {
                                debug.error(method + "ERRORE chiamata rest [" + idmRestURL + "] IDM user ["
                                        + usrIdentity.getName() + "]:: " + e.getMessage());
                            }
                        } else {
                            if (debug.messageEnabled())
                                debug.message(method + " aggiornamento IDM non effettuato per user["
                                        + usrIdentity.getName() + "]:: aggiornamento non necessario");
                        }
                    } else {
                        if (debug.messageEnabled())
                            debug.message(method + " chiamata rest IDM disabilitata per Base URL nullo o vuoto ");
                    }

                    return true;
                }
            } else
                debug.error(method + "Errore attributeMap NULL!!!");
        } catch (SSOException e) {
            debug.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            debug.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    /**
     * NOTA: In caso di aggiunta di un attributo LDAP da modificare ricordarsi di
     * aggiungere il mapping IDM
     *
     * @param attributeMap Attributi del map definito sull'SP spid
     * @param attributes   Attrbiuti asserzione SAML
     * @param userID       Nome utente
     * @param userAttrMap  Map contente gli attributi da impostare
     * @return Lo stesso map dell'input userAttrMap con l'aggiunta degli attributi
     *         SAML mappati
     * @throws ParseException
     */
    private Map<String, List<?>> setUpdateUserAttrMap(Map<String, List<String>> attributeMap,
            List<Attribute> attributes, String userID, Map<String, List<?>> userAttrMap)
            throws ParseException {
        String method = "[setUpdateUserAttrMap]";
        if (debug.messageEnabled())
            debug.message(method + "inizio ... ");

        if (debug.messageEnabled())
            debug.message(method + "******* INIZIO Iterator User [" + userID + "] - Attributi Asserzione ********");
        for (Iterator<Attribute> iter = attributes.iterator(); iter.hasNext();) {
            Attribute attribute = iter.next();
            if (attribute.getName() != null && attribute.getAttributeValueString() != null) {
                if (getAttrAssertion(attribute.getAttributeValueString()) != null &&
                        !getAttrAssertion(attribute.getAttributeValueString()).equals("-")) {
                    if (attribute.getName().equalsIgnoreCase("fiscalNumber")
                            && attribute.getAttributeValueString() != null) {
                        String codfisc = getAttrAssertion(attribute.getAttributeValueString());
                        if (codfisc != null && codfisc.length() >= TINSUFF.length()) {
                            userAttrMap.put(getCorrAttrLDAP(attributeMap, "fiscalNumber"),
                                    Arrays.asList(codfisc.substring(TINSUFF.length())));
                            if (debug.messageEnabled())
                                debug.message(method + "Attr Assertion MAP - fiscalNumber: "
                                        + codfisc.substring(TINSUFF.length()));
                        }
                    } else if (attribute.getName().equalsIgnoreCase(SPID_IVACODE_ATTRNAME)
                            && attribute.getAttributeValueString() != null) {
                        // TODO che fare in caso di cambio partita iva ...
                        String ivaCode = getAttrAssertion(attribute.getAttributeValueString());
                        if (ivaCode != null && ivaCode.length() >= VATSUFF.length())
                            userAttrMap.put(getCorrAttrLDAP(attributeMap, attribute.getName()),
                                    Arrays.asList(ivaCode.substring(VATSUFF.length())));
                    } else if (attribute.getName().equalsIgnoreCase("email")
                            && attribute.getAttributeValueString() != null) {
                        // attributo SpidMail
                        String sSpidEmail = getAttrAssertion(util.getAttributeVal(attributes, "email"));
                        if (debug.messageEnabled())
                            debug.message(method + " -- (" + SPID_MAIL_ATTR + "): " + sSpidEmail);
                        userAttrMap.put(SPID_MAIL_ATTR, Arrays.asList(sSpidEmail));
                    } else if (attribute.getName().equalsIgnoreCase("mobilePhone")
                            && attribute.getAttributeValueString() != null) {
                        // attributo SpidMobile
                        String sSpidMobile = getAttrAssertion(util.getAttributeVal(attributes, "mobilePhone"));
                        if (debug.messageEnabled())
                            debug.message(method + " -- (" + SPID_MOBILE_ATTR + "): " + sSpidMobile);
                        userAttrMap.put(SPID_MOBILE_ATTR, Arrays.asList(sSpidMobile));
                    } else {
                        List<String> lAttrLDAP = getAllCorrAttrLDAP(attributeMap, attribute.getName());
                        String attrLDAPVal = getAttrAssertion(attribute.getAttributeValueString());
                        if (lAttrLDAP != null) { // aggiunto
                            for (String attrLDAP : lAttrLDAP) {
                                if (debug.messageEnabled())
                                    debug.message(
                                            method + "Generic Attr Assertion MAP - " + attrLDAP + " : " + attrLDAPVal);
                                userAttrMap.put(attrLDAP, Arrays.asList(attrLDAPVal));
                            }
                        }
                    }
                } else {
                    // Attributo SAML nullo o vuoto
                    if (attribute.getName().equalsIgnoreCase("fiscalNumber")
                            && attribute.getAttributeValueString() != null) {
                        // userAttrMap.put(getCorrAttrLDAP(attributeMap, "fiscalNumber"), null );
                        debug.error(method + "Attr Assertion MAP - fiscalNumber: NULL !!!");
                    } else if (attribute.getName().equalsIgnoreCase(SPID_IVACODE_ATTRNAME)
                            && attribute.getAttributeValueString() != null) {
                        // TODO che fare in caso di Partira IVA NULL ...
                        userAttrMap.put(getCorrAttrLDAP(attributeMap, attribute.getName()), null);
                        if (debug.messageEnabled())
                            debug.message(method + "Attr Assertion MAP - " + SPID_IVACODE_ATTRNAME + ": NULL !!!");
                    } else if (attribute.getName().equalsIgnoreCase("email")
                            && attribute.getAttributeValueString() != null) {
                        // attributo SpidMail
                        userAttrMap.put(SPID_MAIL_ATTR, null);
                        if (debug.messageEnabled())
                            debug.message(method + " -- (" + SPID_MAIL_ATTR + "): NULL!!! ");
                    } else if (attribute.getName().equalsIgnoreCase("mobilePhone")
                            && attribute.getAttributeValueString() != null) {
                        // attributo SpidMobile
                        userAttrMap.put(SPID_MOBILE_ATTR, null);
                        if (debug.messageEnabled())
                            debug.message(method + " -- (" + SPID_MOBILE_ATTR + "): NULL!! ");
                    } else {
                        List<String> lAttrLDAP = getAllCorrAttrLDAP(attributeMap, attribute.getName());
                        for (String attrLDAP : lAttrLDAP) {
                            if (debug.messageEnabled())
                                debug.message(method + "Generic Attr Assertion MAP - " + attrLDAP + " : NULL!!");
                            userAttrMap.put(getCorrAttrLDAP(attributeMap, attribute.getName()), null);
                        }
                    }
                }
            }
        }
        if (debug.messageEnabled())
            debug.message(method + "******* FINE Iterator User [" + userID + "] - Attributi Asserzione ********");

        /* CDM */
        if (setCDMAttribute) {
            if (debug.messageEnabled())
                debug.message(method + "******* INIZIO setCDMAttribute User [" + userID + "] - Attributi CDM ********");
            // CN
            if (userAttrMap.get("cn") != null)
                userAttrMap.remove("cn");
            String sNome = getAttrAssertion(util.getAttributeVal(attributes, "name"));
            String sCognome = getAttrAssertion(util.getAttributeVal(attributes, "familyName"));
            userAttrMap.put("cn", Arrays.asList(sNome + " " + sCognome));

            // persona Giuridica o Fisica
            String ivaCode = getAttrAssertion(util.getAttributeVal(attributes, SPID_IVACODE_ATTRNAME));
            if (ivaCode != null && !ivaCode.isEmpty() && !ivaCode.equalsIgnoreCase("-")) {
                userAttrMap.put(SPID_CDM_GIURIDICA_FISICA, Arrays.asList("G"));
            } else {
                userAttrMap.put(SPID_CDM_GIURIDICA_FISICA, Arrays.asList("F"));
            }

            // address
            if (getAttrAssertion(util.getAttributeVal(attributes, "address")) != null) {
                try {
                    String sAddress = getAttrAssertion(util.getAttributeVal(attributes, "address"));
                    // Map<String, String> mAddress = getAddressElement(sAddress);

                    userAttrMap.put("address", Arrays.asList(sAddress));

                    // Commentato perchè per la gestione della casistica toponomastica, deve essere
                    // aggiornato solo il campo address
                    /*
                     * if (mAddress != null && mAddress.size() > 0) {
                     * if (userAttrMap.get("street") != null)
                     * userAttrMap.remove("street");
                     * if (mAddress.get("default") != null) {
                     * userAttrMap.put("street", Arrays.asList(mAddress.get("default")));
                     * } else {
                     * userAttrMap.put("postalCode", Arrays.asList(mAddress.get("postalCode")));
                     * if (mAddress.get("st") != null) {
                     * userAttrMap.put("st", Arrays.asList(mAddress.get("st")));
                     * }
                     * userAttrMap.put("street", Arrays.asList(mAddress.get("street").toString()));
                     * }
                     * }
                     */
                } catch (IndexOutOfBoundsException ex) {
                    debug.error(method, ex.getLocalizedMessage());
                }
            }

            // aggiunto attributo cdmNascitaData
            if (getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")) != null &&
                    !getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")).isEmpty()) {
                DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
                String sdataNascDate = getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth"));
                if (debug.messageEnabled())
                    debug.message(method + " -- (sdataNascDate): " + sdataNascDate);
                Date dataNascDate = dateFormat.parse(sdataNascDate);

                // cdmNascitaData
                userAttrMap.put("cdmNascitaData",
                        Arrays.asList(new SimpleDateFormat("yyyyMMdd000000").format(dataNascDate)));
            }

            if (debug.messageEnabled())
                debug.message(method + "******* FINE setCDMAttribute User [" + userID + "] - Attributi CDM ********");
        }

        return userAttrMap;
    }

    /**
     * Calcola il MailChanged-Flag per la pagina di post login
     *
     * @param assertionMailAttrVal -> Valore email presente nell'asserzione.
     * @param ldapSPIDMailAttrVal  -> Valore SPIDmail presente su LDAP
     * @param ldapMailAttrVal      -> Valore SPIDmail presente su LDAP
     * @return String -> il valore del flag mailChangedFlag
     */
    public String checkMailChangedFlag(String assertionMailAttrVal, String ldapSPIDMailAttrVal,
            String ldapMailAttrVal) {
        String method = "[checkMailChangedFlag]:: ";

        // Se l'attributo dell'asserzione � diverso dagli attributi LDAP mail e
        // SPIDEmail imposto a true il relativo flag
        if (assertionMailAttrVal != null && !assertionMailAttrVal.isEmpty()) {
            if (ldapSPIDMailAttrVal != null && !assertionMailAttrVal.equalsIgnoreCase(ldapSPIDMailAttrVal)) {
                if (ldapMailAttrVal != null && !assertionMailAttrVal.equalsIgnoreCase(ldapMailAttrVal)) {
                    if (debug.messageEnabled())
                        debug.message(method + "rilevato cambio email, imposto mailChangedFlag a true ");
                    return "true";
                }
            } else if (ldapSPIDMailAttrVal == null && ldapMailAttrVal != null
                    && !assertionMailAttrVal.equalsIgnoreCase(ldapMailAttrVal)) {
                if (debug.messageEnabled())
                    debug.message(method + "ldapSPIDMailAttrVal null, imposto mailChangedFlag a true ");
                return "true";
            }
        } else {
            if (debug.messageEnabled())
                debug.message(method + "attributo email non presente nell'asserzione ");
        }
        return "false";
    }

    /**
     * Calcola il MobileChanged-Flag per la pagina di post login
     *
     * @param assertionMobileAttrVal -> Valore mobile presente nell'asserzione.
     * @param ldapSPIDMobileAttrVal  -> Valore SPIDmobile presente su LDAP
     * @param ldapMobileAttrVal      -> Valore SPIDmobile presente su LDAP
     * @return String -> il valore del flag mobileChangedFlag
     */
    public String checkMobileChangedFlag(String assertionMobileAttrVal, String ldapSPIDMobileAttrVal,
            String ldapMobileAttrVal) {
        String method = "[checkMobileChangedFlag]:: ";

        // Se l'attributo dell'asserzione � diverso dagli attributi LDAP mobile e
        // SPIDMobile imposto a true il relativo flag
        if (assertionMobileAttrVal != null && !assertionMobileAttrVal.isEmpty()) {
            if (ldapSPIDMobileAttrVal != null && !assertionMobileAttrVal.replaceAll("^(\\+39|0039)", "")
                    .equalsIgnoreCase(ldapSPIDMobileAttrVal.replaceAll("^(\\+39|0039)", ""))) {
                if (ldapMobileAttrVal != null && !assertionMobileAttrVal.replaceAll("^(\\+39|0039)", "")
                        .equalsIgnoreCase(ldapMobileAttrVal.replaceAll("^(\\+39|0039)", ""))) {
                    if (debug.messageEnabled())
                        debug.message(method + "rilevato cambio mobilePhone, imposto mobileChangedFlag a true ");
                    return "true";
                }
            } else if (ldapSPIDMobileAttrVal == null && ldapMobileAttrVal != null
                    && !assertionMobileAttrVal.replaceAll("^(\\+39|0039)", "")
                            .equalsIgnoreCase(ldapMobileAttrVal.replaceAll("^(\\+39|0039)", ""))) {
                if (debug.messageEnabled())
                    debug.message(method + "ldapSPIDMobileAttrVal null, imposto mobileChangedFlag a true ");
                return "true";
            }
        } else {
            if (debug.messageEnabled())
                debug.message(method + "attributo mobilePhone non presente nell'asserzione ");
        }
        return "false";
    }

    /**
     * Calcola l'addressChanged-Flag per la pagina di post login
     *
     * Il metodo controlla se l'attributo dell'asserzione è diverso
     * dall'attributo address LDAP ed è diverso dal campo street LDAP imposto a true
     * il relativo flag.
     * 
     * @param assertionAddressAttrVal -> Valore address presente nell'asserzione.
     * @param ldapAddressAttrVal      -> Valore address presente su LDAP
     * @param ldapStreetAttrVal       -> Valore street presente su LDAP
     * @return String -> il valore del flag addressChangedFlag
     */
    public String checkAddressChangedFlag(String assertionAddressAttrVal, String ldapAddressAttrVal,
            String ldapStreetAttrVal) {
        String method = "[checkAddressChangedFlag]:: ";

        // Se l'attributo dell'asserzione è diverso dall'attributo address LDAP e
        // diverso dall'attributo street LDAP, imposto a true il relativo flag
        // altrimenti imposto a false il flag.
        if (assertionAddressAttrVal != null && !assertionAddressAttrVal.isEmpty()) {
            if (ldapAddressAttrVal != null && !assertionAddressAttrVal.equalsIgnoreCase(ldapAddressAttrVal)) {

                List<String> listStreet = Arrays.asList(
                        ldapStreetAttrVal.toLowerCase().replace("(", "").replace(")", "").replace(",", " ").split(" "));
                List<String> listAddress = Arrays
                        .asList(assertionAddressAttrVal.toLowerCase().replace(",", " ").split(" "));

                // Viene richiamato il metodo checkAllContainsStreetIntoAddress() che controlla
                // se la street LDAP è presente nell'address della SAML
                // Se è presente allora imposto il flag a false(significa che l'indirizzo non è
                // cambiato), altrimenti a true
                if (checkAllContainsStreetIntoAddress(listStreet, listAddress)) {
                    return "false";
                } else {
                    return "true";
                }

                // Non dovrebbe scattare mai
            } else if (ldapAddressAttrVal == null) {
                if (debug.messageEnabled())
                    debug.message(method + "ldapAddressAttrVal null, imposto addressChangedFlag a true");
                return "true";
            }
        } else {
            if (debug.messageEnabled())
                debug.message(method + "attributo address non presente nell'asserzione");
        }
        return "false";
    }

    /**
     * Metodo che controlla se il valore del campo LDAP street è presente nel valore
     * del campo address della SAML.
     * 
     * @param listStreet              List che contiene la street splittata
     * @param listAddress             List che contiene l'address splittata
     * @param assertionAddressAttrVal Valore del campo address della SAML
     * @return
     */
    public Boolean checkAllContainsStreetIntoAddress(List<String> listStreet, List<String> listAddress) {
        String method = "[checkAllContainsStreetIntoAddress]::";

        if (debug.messageEnabled()) {
            debug.message(method
                    + " Inzio il controllo della street con il valore dell'address proveniente dall'assertion...");
        }

        // Usa un set per cercare parole con match esatto
        Set<String> fullSet = new HashSet<>(listAddress);

        // Tutte le parole devono essere presenti come parola esatta
        return listStreet.stream().allMatch(fullSet::contains);
    }

    /**
     * Converte il modifyTimestamp LDAP in una data
     *
     * @param ldapDate -> data LDAP in formato stringa, dateFormat yyyyMMddHHmmssZ,
     *                 TimeZone GMT.
     * @return Date
     */
    public static Date parseLdapDate(String ldapDate) {
        String method = "[parseLdapDate]:: ";

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
        ldapDate = ldapDate.replace("Z", "");
        try {
            return sdf.parse(ldapDate);
        } catch (ParseException e) {
            e.printStackTrace();
            if (ldapDate == null)
                debug.error(method + "ldapDate is NULL");
            else
                debug.error(method + "errore durante il parsing di ldapDate");
        }
        return null;
    }

    /**
     * Calcola i flags per la pagina di post login eseguendo una ricerca sullo user
     * store
     *
     * @param realm        -> Realm dell'SP hosted.
     * @param ssoResponse  -> Response dall'IDP
     * @param hostEntityID -> EntityID dell'hosted SP
     * @return HashMap<String, String> -> i valori dei 5 flags newCreationFlag,
     *         mailChangedFlag, mobileChangedFlag, addressChangedFlag e
     *         newCreationknownFlag
     *         ed in caso oldMail, oldMobile e oldAddress che rappresentano i valori
     *         LDAP dell'account SPID pregresso
     */
    public HashMap<String, String> getPostLoginFlags(String realm, Response ssoResponse, String hostEntityID) {
        String method = "[getPostLoginFlags]:: ";
        if (debug.messageEnabled())
            debug.message(method + "inizio ... ");

        // Inizializzo tutti i flags a false
        HashMap<String, String> postLoginFlags = new HashMap<String, String>(); // Mappa contenente i flags
        String newCreationFlag = "false";
        String mailChangedFlag = "false";
        String mobileChangedFlag = "false";
        // Flag aggiunto per la gestione del flusso toponomastica
        String addressChangedFlag = "false";
        String newCreationknownFlag = "false";
        String oldMail = null;
        String oldMobile = null;
        String oldStreet = null;

        String userID = null; // Nome Utente utilizzato per la ricerca su LDAP
        Assertion assertion = null;
        List<AttributeStatement> attributeStatements = null;
        List<Attribute> assertionAttributes = null; // Lista degli attributi provenienti dall'asserzione SAML

        try {
            // Recupero l'asserzione dalla ssoResponse ed i suoi attributi
            if (ssoResponse != null && ssoResponse.getAssertion() != null) {
                assertion = ssoResponse.getAssertion().get(0);
                attributeStatements = assertion.getAttributeStatements();
            } else
                debug.error(method + "ssoResponse null o impossibile estrarre asserzione ");
            // Inserisco in una Lista gli attributi dell'attributeStatements dall'asserzione
            if (attributeStatements != null) {
                assertionAttributes = attributeStatements.get(0).getAttribute();
            } else
                debug.error(method + "attributeStatements null ");

            // Recupero l'attributo da utilizzare per la ricerca dell'utente
            if (assertionAttributes != null) {
                // Se l'autofederazione � attiva recupero l'attributo di autofederazione per
                // utilizzarlo nella ricerca utente
                String useAutoFed = getAttribute(realm, hostEntityID, SAML2Constants.AUTO_FED_ENABLED);
                if ((useAutoFed != null) && useAutoFed.equalsIgnoreCase("true")) {
                    // Recupero il nome dell'attributo
                    String autoFedAttr = getAttribute(realm, hostEntityID, SAML2Constants.AUTO_FED_ATTRIBUTE);
                    if (debug.messageEnabled())
                        debug.message(method + "attributo di auto federazione autoFedAttr: " + autoFedAttr);
                    if (autoFedAttr != null) {
                        if (debug.messageEnabled())
                            debug.message(method + "utilizzo l'attributo di auto federazione come UserID");
                        // Recupero il valore dell'attributo
                        userID = getAttrAssertion(util.getAttributeVal(assertionAttributes, autoFedAttr));
                        // Eseguo il substring nel caso inizi con il prefisso TINSUFF
                        if (userID != null && userID.startsWith(TINSUFF))
                            userID = userID.substring(TINSUFF.length());
                        if (debug.messageEnabled())
                            debug.message(method + "userID: " + userID);
                    } else
                        debug.error(method + "attributo di autofederazione NON definito.");
                } else { // Altrimenti utilizzo il nameID (se indicato nell'Entity Provider)
                    // Recupero il NameID dall'asserzione
                    NameID nameID = util.getNameID(assertion, hostEntityID, realm);
                    if (nameID != null && nameID.getValue() != null) {
                        // Controllo se nella configurazione dell'Entity Provider � indicato di
                        // utilizzare il NameID come UserID
                        String useNameID = getAttribute(realm, hostEntityID, SAML2Constants.USE_NAMEID_AS_SP_USERID);
                        if ((useNameID != null) && useNameID.equalsIgnoreCase("true")) {
                            if (debug.messageEnabled())
                                debug.message(method + "utilizzo NameID come UserID");
                            // Recupero il valore del nameID
                            userID = nameID.getValue().toUpperCase();
                            // Eseguo il substring nel caso inizi con il prefisso TINSUFF
                            if (userID != null && userID.startsWith(TINSUFF))
                                userID = userID.substring(TINSUFF.length());
                            if (debug.messageEnabled())
                                debug.message(method + "userID: " + userID);
                        } else
                            debug.error(method + "useNameID NULL or useNameID is FALSE : " + useNameID);
                    } else
                        debug.error(method + "NameID from assertion null ");
                }
            } else
                debug.error(method + "nessun attributo trovato nell'asserzione SAML ");

            // Eseguo la ricerca dell'utente
            if (userID != null && !userID.isEmpty()) {
                List<AMIdentity> users = repoUtil.getUserStoreIdentity(userID, realm);

                String assertionMailAttrVal = getAttrAssertion(util.getAttributeVal(assertionAttributes, "email")); // Attributo
                                                                                                                    // email
                                                                                                                    // dall'asserzione
                String assertionMobileAttrVal = getAttrAssertion(
                        util.getAttributeVal(assertionAttributes, "mobilePhone")); // Attributo mobile dall'asserzione
                String assertionAddressAttrVal = getAttrAssertion(util.getAttributeVal(assertionAttributes, "address")); // Attributo
                                                                                                                         // address
                                                                                                                         // dall'asserzione

                // Se l'utente non esiste ancora verifico se impostare il flag newCreation o
                // newCreationknown a true
                if (users == null || users.isEmpty()) {

                    // Se searchUserAttr presente innesco la nuova logica di ricerca degli account
                    // SPID pregressi
                    if (searchUserAttr != null && !searchUserAttr.isEmpty()) {

                        // Recupero gli attributi per il searchFilter
                        String[] attributesValue = null;
                        attributesValue = searchUserAttr.split(";");
                        HashMap<String, Set<String>> searchFilter = new HashMap<String, Set<String>>();

                        for (String attr : attributesValue) {
                            StringTokenizer st = new StringTokenizer(attr, "=");
                            String attrLdap = st.nextToken();
                            String attrAssertion = st.nextToken();
                            Boolean isStringaFissa = false;
                            Set<String> set = new HashSet<String>();

                            isStringaFissa = attrAssertion.startsWith("$");

                            // Se l'attributo � una stringa fissa la inserisco direttamente nel searchFilter
                            // Altrimenti recupero il valore presente nell'asserzione per l'attributo
                            // indicato
                            if (!isStringaFissa) {
                                List<?> userVal = util.getAttributeVal(assertionAttributes, attrAssertion);
                                if (userVal.get(0) != null) {
                                    if (userVal.get(0).toString().startsWith(TINSUFF)) {
                                        String attrVal = userVal.get(0).toString().substring(TINSUFF.length());
                                        set.add(attrVal);
                                    } else {
                                        set.add(userVal.get(0).toString());
                                    }
                                    searchFilter.put(attrLdap, set);
                                }
                            } else {
                                set.add(attrAssertion.replace("$", ""));
                                searchFilter.put(attrLdap, set);
                            }
                        }

                        // Eseguo ricerca di account pregressi utilizzando gli attributi passati da
                        // console AM in spid.searchuser.attribute
                        users = repoUtil.getUserStoreIdentityQueryAnd(searchFilter, realm);

                        // Se non trovo utenti pregressi innesco semplicemente il newCreationFlag a true
                        if (users == null || users.isEmpty()) {
                            newCreationFlag = "true";
                            if (debug.messageEnabled())
                                debug.message(method + "nessun utente trovato, imposto newCreationFlag a true");
                        } else {
                            // Altrimenti imposto il newCreationknownFlag a true
                            newCreationknownFlag = "true";
                            if (debug.messageEnabled())
                                debug.message(method
                                        + "nuovo utente con account SPID pregressi, imposto newCreationknownFlag a true");

                            // Verifico se impostare a "true" i flags mailChangedFlag e mobileChangedFlag
                            // basandomi sugli account pregressi
                            AMIdentity lastUserIdentity = null;

                            // In caso di pi� account pregressi prendo quello con modifyTimestamp pi�
                            // recente
                            if (users.size() > 1) {
                                Date lastModifyTimestamp = null;
                                for (AMIdentity user : users) {
                                    String modifyTimestamp = getAttrFromSet(user.getAttribute("modifyTimestamp"));
                                    if (debug.messageEnabled())
                                        debug.message(method + "account pregresso " + user.getName().toString()
                                                + ", modifyTimestamp " + modifyTimestamp);

                                    Date ldapDate = parseLdapDate(modifyTimestamp);
                                    if (lastModifyTimestamp != null && ldapDate != null) {
                                        if (lastModifyTimestamp.compareTo(ldapDate) < 0) {
                                            lastModifyTimestamp = ldapDate;
                                            lastUserIdentity = user;
                                            if (debug.messageEnabled())
                                                debug.message(method
                                                        + "lastModifyTimestamp � maggiore di ldapDate, per ora questo � l'utente pi� recente");
                                        } else {
                                            if (debug.messageEnabled())
                                                debug.message(method
                                                        + "lastModifyTimestamp � minore di ldapDate, l'utente non � il pi� recente");
                                        }
                                    } else {
                                        lastUserIdentity = user;
                                        lastModifyTimestamp = ldapDate;
                                        if (debug.messageEnabled())
                                            debug.message(method
                                                    + "primo account ciclato, per ora considero questo come utente modificato pi� recentemente");
                                    }
                                }
                                if (debug.messageEnabled())
                                    debug.message(method + "account pregresso pi� recente = "
                                            + lastUserIdentity.getName().toString());
                            } else {
                                // Altrimenti prendo l'unico utente rilevato
                                lastUserIdentity = users.get(0);
                                if (debug.messageEnabled())
                                    debug.message(
                                            method + "account pregresso " + lastUserIdentity.getName().toString());
                            }

                            Map<String, List<String>> attrMap = getAttributeMap(hostEntityID, realm); // Mappa dei nomi
                                                                                                      // degli attributi
                                                                                                      // Asserzione=LDAP
                                                                                                      // (presi da
                                                                                                      // console AM)

                            /* -- Verifica dell'attributo Mail -- */
                            String ldapMailAttr = getCorrAttrLDAP(attrMap, "email"); // Nome dell'attributo LDAP
                                                                                     // corrispondente a email
                            String ldapMailAttrVal = getAttrFromSet(lastUserIdentity.getAttribute(ldapMailAttr)); // Attuale
                                                                                                                  // attributo
                                                                                                                  // mail
                                                                                                                  // dall'LDAP
                            String ldapSPIDMailAttrVal = getAttrFromSet(lastUserIdentity.getAttribute("SPIDEmail")); // Attuale
                                                                                                                     // attributo
                                                                                                                     // SPIDEmail
                                                                                                                     // dall'LDAP

                            mailChangedFlag = checkMailChangedFlag(assertionMailAttrVal, ldapSPIDMailAttrVal,
                                    ldapMailAttrVal);

                            if (mailChangedFlag.equalsIgnoreCase("true")) {
                                oldMail = ldapMailAttr + "=" + ldapMailAttrVal;
                                if (debug.messageEnabled())
                                    debug.message(
                                            method + "rilevato mailChangedFlag da account pregresso, imposto oldMail = "
                                                    + oldMail);
                            }

                            /* -- Verifica dell'attributo Mobile -- */
                            String ldapMobileAttr = getCorrAttrLDAP(attrMap, "mobilePhone"); // Nome dell'attributo LDAP
                                                                                             // corrispondente a
                                                                                             // mobilePhone
                            String ldapMobileAttrVal = getAttrFromSet(lastUserIdentity.getAttribute(ldapMobileAttr)); // Attuale
                                                                                                                      // attributo
                                                                                                                      // mobile
                                                                                                                      // dall'LDAP
                            String ldapSPIDMobileAttrVal = getAttrFromSet(lastUserIdentity.getAttribute("SPIDMobile")); // Attuale
                                                                                                                        // attributo
                                                                                                                        // SPIDMobile
                                                                                                                        // dall'LDAP

                            mobileChangedFlag = checkMobileChangedFlag(assertionMobileAttrVal, ldapSPIDMobileAttrVal,
                                    ldapMobileAttrVal);

                            if (mobileChangedFlag.equalsIgnoreCase("true")) {
                                oldMobile = ldapMobileAttr + "=" + ldapMobileAttrVal;
                                if (debug.messageEnabled())
                                    debug.message(method
                                            + "rilevato mobileChangedFlag da account pregresso, imposto oldMobile = "
                                            + oldMobile);
                            }

                            /* -- Verifica dell'attributo Address -- */
                            /*
                             * String ldapAddressAttrVal =
                             * getAttrFromSet(lastUserIdentity.getAttribute("street")); // Attuale attributo
                             * street dall'LDAP
                             * String ldapSPIDAddressAttrVal =
                             * getAttrFromSet(lastUserIdentity.getAttribute("address")); // Attuale
                             * attributo address dall'LDAP
                             * 
                             * streetChangedFlag =
                             * checkAddressChangedFlag(assertionAddressAttrVal,ldapSPIDAddressAttrVal,
                             * ldapAddressAttrVal);
                             * 
                             * if (streetChangedFlag.equalsIgnoreCase("true")) {
                             * oldStreet = "street =" + ldapAddressAttrVal;
                             * if (debug.messageEnabled())
                             * debug.message(method +
                             * "rilevato addressChangedFlag da account pregresso, imposto oldStreet = " +
                             * oldStreet);
                             * }
                             */
                        }
                    } else { // Altrimenti imposto semplicemente newCreationFlag a true
                        newCreationFlag = "true";
                        if (debug.messageEnabled())
                            debug.message(method + "nessun utente trovato, imposto newCreationFlag a true");
                    }
                } else { // Altrimenti verifico se impostare a "true" i flags mailChangedFlag e
                         // mobileChangedFlag

                    AMIdentity userIdentity = users.get(0);
                    Map<String, List<String>> attrMap = getAttributeMap(hostEntityID, realm); // Mappa dei nomi degli
                                                                                              // attributi
                                                                                              // Asserzione=LDAP (presi
                                                                                              // da console AM)
                    if (debug.messageEnabled())
                        debug.message(method + "utente " + userIdentity.getName().toString() + " trovato ");

                    /* -- Verifica dell'attributo Mail -- */
                    String ldapMailAttr = getCorrAttrLDAP(attrMap, "email"); // Nome dell'attributo LDAP corrispondente
                                                                             // a email
                    String ldapMailAttrVal = getAttrFromSet(userIdentity.getAttribute(ldapMailAttr)); // Attuale
                                                                                                      // attributo mail
                                                                                                      // dall'LDAP
                    String ldapSPIDMailAttrVal = getAttrFromSet(userIdentity.getAttribute("SPIDEmail")); // Attuale
                                                                                                         // attributo
                                                                                                         // SPIDEmail
                                                                                                         // dall'LDAP

                    mailChangedFlag = checkMailChangedFlag(assertionMailAttrVal, ldapSPIDMailAttrVal, ldapMailAttrVal);

                    /* -- Verifica dell'attributo Mobile -- */
                    String ldapMobileAttr = getCorrAttrLDAP(attrMap, "mobilePhone"); // Nome dell'attributo LDAP
                                                                                     // corrispondente a mobilePhone
                    String ldapMobileAttrVal = getAttrFromSet(userIdentity.getAttribute(ldapMobileAttr)); // Attuale
                                                                                                          // attributo
                                                                                                          // mobile
                                                                                                          // dall'LDAP
                    String ldapSPIDMobileAttrVal = getAttrFromSet(userIdentity.getAttribute("SPIDMobile")); // Attuale
                                                                                                            // attributo
                                                                                                            // SPIDMobile
                                                                                                            // dall'LDAP

                    mobileChangedFlag = checkMobileChangedFlag(assertionMobileAttrVal, ldapSPIDMobileAttrVal,
                            ldapMobileAttrVal);

                    /*
                     * -- Verifica dell'attributo Address per la challenge della logica del flusso
                     * toponomastica --
                     */

                    // Attuale attributo street del LDAP
                    String ldapStreetAttrVal = getAttrFromSet(userIdentity.getAttribute("street"));

                    // Attuale attributo address del LDAP
                    String ldapAddressAttrVal = getAttrFromSet(userIdentity.getAttribute("address"));

                    addressChangedFlag = checkAddressChangedFlag(assertionAddressAttrVal, ldapAddressAttrVal,
                            ldapStreetAttrVal);

                }
            } else
                debug.error(method + "impossibile recuperare userID da asserzione");
        } catch (Exception e) {
            debug.error(method + "Exception: ", e);
        }
        postLoginFlags.put("newCreationFlag", newCreationFlag);
        postLoginFlags.put("mailChangedFlag", mailChangedFlag);
        postLoginFlags.put("mobileChangedFlag", mobileChangedFlag);
        postLoginFlags.put("addressChangedFlag", addressChangedFlag);
        // Gestione account pregressi
        postLoginFlags.put("newCreationknownFlag", newCreationknownFlag);
        postLoginFlags.put("oldMail", oldMail);
        postLoginFlags.put("oldMobile", oldMobile);
        postLoginFlags.put("oldStreet", oldStreet);

        if (debug.messageEnabled())
            debug.message(method + "postLoginFlags: " + Arrays.asList(postLoginFlags));
        return postLoginFlags;
    }

    /**
     * Metodo che richiama l'api di IDM per interrogare il managed comuni.
     * Questo serve per eseguire la casistica di ricerca con il codiceComune(da cui
     * devo ottenere il nomeComune) oppure
     * la casistica di ricerca con il nomeComune(da cui devo ottenere il
     * codiceComune).
     * Questo metodo aggiorna userAttrMap inserendo o l'attributo LDAP "l" o
     * "cdmResidenzaCodiceComune", in base alla
     * casistica di ricerca.
     * 
     * @param flagInput True attiva la ricerca del codiceComune, False attiva la
     *                  ricerca del nomeComune
     * @param input     Il valore del codiceComune o nomeComune con cui fare la
     *                  ricerca
     * 
     * @throws IOException
     * @throws JSONException
     * @throws KeyManagementException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public void sendGETComuni(String idmRestURLComuni, String idmRestURL_admin, String idmRestURL_pwd,
            Boolean flagInput, String input,
            Map<String, List<?>> userAttrMap)
            throws IOException, JSONException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        String method = "[sendGETComuni]:: ";

        CloseableHttpClient httpClient = HttpClients.createDefault();
        BufferedReader reader = null;
        JSONObject userJsonObject = null;
        String sURL = null;

        try {

            // sURL =
            // "https://openidm7.test.comune/openidm/managed/Comuni?_queryFilter=true";
            sURL = idmRestURLComuni;

            // httpClient = noSslHttpClient();

            HttpGet httpGet = new HttpGet(sURL);
            httpGet.addHeader("X-OpenIDM-Username", idmRestURL_admin);
            httpGet.addHeader("X-OpenIDM-Password", idmRestURL_pwd);
            httpGet.addHeader("Content-Type", "application/json");

            CloseableHttpResponse httpResponse = httpClient.execute(httpGet);

            if (httpResponse != null && httpResponse.getStatusLine() != null
                    && httpResponse.getStatusLine().getStatusCode() == 200) {
                reader = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

                String inputLine;
                StringBuffer response = new StringBuffer();

                while ((inputLine = reader.readLine()) != null) {
                    response.append(inputLine);
                }

                // converte la response in JSON
                JSONObject responseJsonObject = new JSONObject(response.toString());

                // Casistica se abbiamo nome comune dobbiamo trovate il codice
                if (flagInput) {

                    if (debug.messageEnabled())
                        debug.message(method
                                + " Siamo nella casistica dove abbiamo il nome del comune e dobbiamo trovare il codice");

                    String comune = input;

                    JSONArray result = responseJsonObject.getJSONArray("result");
                    for (int i = 0; i < result.length(); i++) {
                        userJsonObject = new JSONObject(result.get(i).toString());
                        if (userJsonObject.getString("nome").toLowerCase().equals(comune.toLowerCase())) {

                            if (debug.messageEnabled())
                                debug.message(method
                                        + "[cdmResidenzaCodiceComune] = " + "[" + userJsonObject.getString("codice")
                                        + "]");

                            userAttrMap.put("cdmResidenzaCodiceComune",
                                    Arrays.asList(userJsonObject.getString("codice")));

                        }
                    }
                } else {

                    if (debug.messageEnabled())
                        debug.message(method
                                + " Siamo nella casistica dove abbiamo il codice del comune e dobbiamo trovare il nome");

                    // Casistica se abbiamo il codice e dobbiamo trovate il nome del comune
                    String codice = input;
                    JSONArray result = responseJsonObject.getJSONArray("result");

                    for (int i = 0; i < result.length(); i++) {

                        userJsonObject = new JSONObject(result.get(i).toString());

                        if (userJsonObject.getString("codice").equals(codice)) {
                            if (debug.messageEnabled())
                                debug.message(method
                                        + " [l] = " + "[" + userJsonObject.getString("nome") + "]");

                            userAttrMap.put("l", Arrays.asList(userJsonObject.getString("nome")));
                        }
                    }
                }
            } else {
                System.out.println(
                        method + "GET Response Status ERROR :: " + httpResponse.getStatusLine().getStatusCode());
            }

        } catch (IOException e) {
            System.out.println(method + e.getMessage());
        } finally {
            reader.close();
            httpClient.close();
        }

    }

}
