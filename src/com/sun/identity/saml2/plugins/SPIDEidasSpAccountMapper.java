package com.sun.identity.saml2.plugins;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.Month;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.util.ArrayMap;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOException;
import com.sun.identity.custom.util.CustomFederationUtil;
import com.sun.identity.custom.util.CustomRepoUtil;
import com.sun.identity.custom.util.CustomEidasRestUtil;
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
public class SPIDEidasSpAccountMapper<ele> extends DefaultLibrarySPAccountMapper {
    // private PrivateKey decryptionKey = null;
    private static final String JAR_VERSION = "6.8"; // TODO

    /**
     * Regole di compilazione della console OpenAM:
     * aggiungere i seguenti attributi globali nelle advanced properties (Configure
     * > Server Defaults > Advanced)
     * - eidas.createuser.enable : se deve essere abilitata la creazione utente
     * - eidas.createuser.ws : se deve essere abilitata la creazione utente via WS
     * specificare l'url del servizio
     * - eidas.createuser.static.attribute: specifica una lista di attributi statici
     * da popolare in creazione dell'utenza
     * - eidas.createuser.create.cdm.attribute.flag : flag specifico per il Comune
     * di Milano - se abilitato imposta degli attributi specifici //CDM
     * - eidas.searchuser.flag: se abilitato ricerca l'utente
     * - eidas.searchuser.attribute: se abilitato il flag precedente specificare
     * l'attributo per la ricerca utente cittadino EX.
     * uid=spidCode;cdmCodiceFiscale=fiscalNumber
     * - eidas.searchpiva.attribute: se abilitato il flag precedente specificare
     * l'attributo per la ricerca utenti partita iva EX. cdmPartitaIva=ivaCode
     * PER IDM
     * - spid.createuser.idm.ws : se deve essere abilitata la creazione utente via
     * WS IDM specificare l'url del servizio
     * - spid.idm.ws.credential.user : utenza per chiamate rest IDM
     * - spid.idm.ws.credential.password : password per chiamate rest IDM
     */
    // add these attributes as advanced properties for CREATE USER FUNCTION
    private static final String GLOBAL_PROP_CREATEUSER_ENABLE = "eidas.createuser.enable";
    private static final String GLOBAL_PROP_CREATEUSER_BASEDN = "eidas.createuser.enable.basedn";
    private static final String GLOBAL_PROP_CREATEUSER_WS = "eidas.createuser.ws";
    private static final String GLOBAL_PROP_CREATEUSER_ATTRIBUTE = "eidas.createuser.static.attribute";
    private static final String GLOBAL_PROP_UPDATEUSER_ATTRIBUTE = "eidas.updateuser.static.attribute";
    private static final String GLOBAL_PROP_CREATEUSER_SETCDMATTR = "eidas.createuser.create.cdm.attribute.flag";
    /*
     * se impostato a true aggiorna lo stato utente ad Active ad ogni accesso SPID
     */
    private static final String GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS = "eidas.updateuser.enable.cdm.status.flag";
    /*
     * se impostato a true abilita la logica di aggiornamento utente ad ogni accesso
     * SPID
     */
    private static final String GLOBAL_PROP_UPDATEUSER_FLAG = "eidas.updateuser.enable.cdm.flag";

    /*
     * searchuser attribute -> Innesca la ricerca e gestione di account SPID
     * pregressi. La ricerca � in AND
     * attrLDAP=attrAsserzione, oppure attrLDAP=$stringafissa (inserire il dollaro).
     * Ad esempio cdmCodiceFiscale=fiscalNumber;cdmTipoUtente=$3
     */
    private static final String GLOBAL_PROP_SEARCHUSER_ATTR = "eidas.searchuser.attribute";

    private static final String GLOBAL_PROP_SEARCHPIVA_ATTR = "eidas.searchpiva.attribute"; // Aggiunto per gestione
                                                                                            // partita iva

    // Aggiunto per chiamate REST IDM
    private static final String GLOBAL_PROP_CREATEIDMUSER_WS = "spid.createuser.idm.ws"; // "https://openidm.test.comune/openidm"
    private static final String GLOBAL_PROP_IDMWS_USER = "spid.idm.ws.credential.user"; // "openidm-attributeMapper"
    private static final String GLOBAL_PROP_IDMWS_PWD = "spid.idm.ws.credential.password"; // "password"

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

    private static String DBGNAME = "SPIDEidasSpAccountMapper";
    private static Logger logger = null;

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

    /**
     * Default constructor
     */
    public SPIDEidasSpAccountMapper() {
        super();
        if (logger == null) {
            logger = LoggerFactory.getLogger(SPIDEidasSpAccountMapper.class);
        }

        // get advanced properties
        String sEnableCreateFlag = SystemProperties.get(GLOBAL_PROP_CREATEUSER_ENABLE);
        if (sEnableCreateFlag == null || sEnableCreateFlag.trim().equals("")) {
            createUserEnable = false;

            logger.debug(GLOBAL_PROP_CREATEUSER_ENABLE + " undefined: use default value FALSE");
        } else {
            createUserEnable = Boolean.parseBoolean(sEnableCreateFlag);

            logger.debug(GLOBAL_PROP_CREATEUSER_ENABLE + " value: " + createUserEnable);
        }

        userContainer = SystemProperties.get(GLOBAL_PROP_CREATEUSER_BASEDN);
        if (userContainer == null || userContainer.trim().equals("")) {

            logger.debug(GLOBAL_PROP_CREATEUSER_BASEDN + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_CREATEUSER_BASEDN + " value: " + userContainer);
        }

        String strAttributeName = SystemProperties.get(GLOBAL_PROP_CREATEUSER_ATTRIBUTE);
        if (strAttributeName == null || strAttributeName.trim().equals("")) {
            createUserAttr = new HashMap<String, String>();

            logger.debug(GLOBAL_PROP_CREATEUSER_ATTRIBUTE + " undefined: NO user Attribute default set");
        } else {
            String[] aAttributesValue = strAttributeName.split(";");
            for (String attr : aAttributesValue) {
                String[] aAttrValue = attr.split("=");
                createUserAttr.put(aAttrValue[0], aAttrValue[1]);
            }

            logger.debug(GLOBAL_PROP_CREATEUSER_ATTRIBUTE + " value: " + createUserAttr);
        }

        /* CDM */
        String sSetCDMAttribute = SystemProperties.get(GLOBAL_PROP_CREATEUSER_SETCDMATTR);
        if (sSetCDMAttribute == null || sSetCDMAttribute.trim().equals("")) {
            setCDMAttribute = false;

            logger.debug(GLOBAL_PROP_CREATEUSER_SETCDMATTR + " undefined: use default value FALSE");
        } else {
            setCDMAttribute = Boolean.parseBoolean(sSetCDMAttribute);

            logger.debug(GLOBAL_PROP_CREATEUSER_SETCDMATTR + " value: " + setCDMAttribute);
        }

        /*
         * se impostato a true aggiorna lo stato utente ad Active ad ogni accesso SPID
         */
        String sUpdateCDMStatus = SystemProperties.get(GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS);
        if (sUpdateCDMStatus == null || sUpdateCDMStatus.trim().equals("")) {
            updateCDMStatus = false;

            logger.debug(GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS + " undefined: use default value FALSE");
        } else {
            updateCDMStatus = Boolean.parseBoolean(sUpdateCDMStatus);

            logger.debug(GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS + " value: " + updateCDMStatus);
        }

        /*
         * se impostato a true abilita la logica di aggiornamento utente ad ogni accesso
         * SPID
         */
        String sUpdateCDMUser = SystemProperties.get(GLOBAL_PROP_UPDATEUSER_FLAG);
        if (sUpdateCDMUser == null || sUpdateCDMUser.trim().equals("")) {
            updateCDMUser = false;

            logger.debug(GLOBAL_PROP_UPDATEUSER_FLAG + " undefined: use default value FALSE");
        } else {
            updateCDMUser = Boolean.parseBoolean(sUpdateCDMUser);

            logger.debug(GLOBAL_PROP_UPDATEUSER_FLAG + " value: " + updateCDMUser);
        }

        searchUserAttr = SystemProperties.get(GLOBAL_PROP_SEARCHUSER_ATTR);
        if (searchUserAttr == null || searchUserAttr.trim().equals("")) {

            logger.debug(GLOBAL_PROP_SEARCHUSER_ATTR + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_SEARCHUSER_ATTR + " value: " + searchUserAttr);
        }

        searchPivaAttr = SystemProperties.get(GLOBAL_PROP_SEARCHPIVA_ATTR);
        if (searchPivaAttr == null || searchPivaAttr.trim().equals("")) {

            logger.debug(GLOBAL_PROP_SEARCHPIVA_ATTR + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_SEARCHPIVA_ATTR + " value: " + searchPivaAttr);
        }

        createUserWs = SystemProperties.get(GLOBAL_PROP_CREATEUSER_WS);
        if (createUserWs == null || createUserWs.trim().equals("")) {

            logger.debug(GLOBAL_PROP_CREATEUSER_WS + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_CREATEUSER_WS + " value: " + createUserWs);
        }

        /*** IDM ***/
        idmRestURL = SystemProperties.get(GLOBAL_PROP_CREATEIDMUSER_WS);
        if (idmRestURL == null || idmRestURL.trim().equals("")) {

            logger.debug(GLOBAL_PROP_CREATEIDMUSER_WS + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_CREATEIDMUSER_WS + " value: " + idmRestURL);
        }

        idmRestURL_admin = SystemProperties.get(GLOBAL_PROP_IDMWS_USER);
        if (idmRestURL_admin == null || idmRestURL_admin.trim().equals("")) {

            logger.debug(GLOBAL_PROP_IDMWS_USER + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_IDMWS_USER + " value: " + idmRestURL_admin);
        }

        idmRestURL_pwd = SystemProperties.get(GLOBAL_PROP_IDMWS_PWD);
        if (idmRestURL_pwd == null || idmRestURL_pwd.trim().equals("")) {

            logger.debug(GLOBAL_PROP_IDMWS_PWD + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_IDMWS_PWD + " value: " + idmRestURL_pwd);
        }

        stringUpdateUserAttr = SystemProperties.get(GLOBAL_PROP_UPDATEUSER_ATTRIBUTE);
        if (stringUpdateUserAttr == null || stringUpdateUserAttr.trim().equals("")) {

            logger.debug(GLOBAL_PROP_UPDATEUSER_ATTRIBUTE + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_UPDATEUSER_ATTRIBUTE + " value: " + stringUpdateUserAttr);
        }
    }

    private void debugAdvancedPropertyVal() {
        String method = "[debugAdvancedPropertyVal]:: ";

        logger.debug(method + "VERSIONE: " + JAR_VERSION);

        logger.debug(method + GLOBAL_PROP_CREATEUSER_ENABLE + " value: " + createUserEnable);

        if (userContainer == null || userContainer.trim().equals("")) {
            logger.debug(GLOBAL_PROP_CREATEUSER_BASEDN + " undefined.");
        } else {
            logger.debug(method + GLOBAL_PROP_CREATEUSER_BASEDN + " value: " + userContainer);
        }

        logger.debug(method + GLOBAL_PROP_CREATEUSER_ATTRIBUTE + " value: " + createUserAttr);

        /* CDM */
        logger.debug(method + GLOBAL_PROP_CREATEUSER_SETCDMATTR + " value: " + setCDMAttribute);

        /*
         * se impostato a true aggiorna lo stato utente ad Active ad ogni accesso SPID
         */
        logger.debug(method + GLOBAL_PROP_UPDATEUSER_SETCDMSTATUS + " value: " + updateCDMStatus);

        /*
         * se impostato a true abilita la logica di aggiornamento utente ad ogni accesso
         * SPID
         */
        logger.debug(method + GLOBAL_PROP_UPDATEUSER_FLAG + " value: " + updateCDMUser);

        if (searchUserAttr == null || searchUserAttr.trim().equals("")) {
            logger.debug(method + GLOBAL_PROP_SEARCHUSER_ATTR + " undefined.");
        } else {
            logger.debug(method + GLOBAL_PROP_SEARCHUSER_ATTR + " value: " + searchUserAttr);
        }

        if (searchPivaAttr == null || searchPivaAttr.trim().equals("")) {
            logger.debug(method + GLOBAL_PROP_SEARCHPIVA_ATTR + " undefined.");
        } else {
            logger.debug(method + GLOBAL_PROP_SEARCHPIVA_ATTR + " value: " + searchPivaAttr);
        }

        if (createUserWs == null || createUserWs.trim().equals("")) {
            logger.debug(method + GLOBAL_PROP_CREATEUSER_WS + " undefined.");
        } else {
            logger.debug(method + GLOBAL_PROP_CREATEUSER_WS + " value: " + createUserWs);
        }

        /*** IDM ***/
        if (idmRestURL == null || idmRestURL.trim().equals("")) {
            logger.debug(method + GLOBAL_PROP_CREATEIDMUSER_WS + " undefined.");
        } else {
            logger.debug(method + GLOBAL_PROP_CREATEIDMUSER_WS + " value: " + idmRestURL);
        }

        if (idmRestURL_admin == null || idmRestURL_admin.trim().equals("")) {
            logger.debug(method + GLOBAL_PROP_IDMWS_USER + " undefined.");
        } else {
            logger.debug(method + GLOBAL_PROP_IDMWS_USER + " value: " + idmRestURL_admin);
        }

        if (idmRestURL_pwd == null || idmRestURL_pwd.trim().equals("")) {
            logger.debug(method + GLOBAL_PROP_IDMWS_PWD + " undefined.");
        } else {
            logger.debug(method + GLOBAL_PROP_IDMWS_PWD + " value: " + idmRestURL_pwd);
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

        // MODIFICA LOG EIDAS AZIENDE
        // Flag per controllare che l'accesso sia di tipo AZIENDE
        boolean flagCompany = false;

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

        logger.debug(method + "assertion.getIssuer().getValue():" + remoteEntityID);

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

            logger.debug(method + "Nome attributo assertion [" + attribute.getName() + "]");
            logger.debug(method + "Valore attributo assertion [" + attribute.getAttributeValueString() + "]");

            // MODIFICA LOG EIDAS AZIENDE
            /**
             * Check per verificare se l'utenza è di tipo Company
             */
            if (attribute.getName().equals("companyName"))
                flagCompany = checkCompany(attribute);

        }

        // LOGICA EIDAS
        // MODIFICA LOG EIDAS
        /**
         * Variabile per recuperare dagli attributi della SAML RESPONSE, il campo per
         * creare l'uid.
         * Levato il check sull'AUTOFEDERATION, perchè il fiscal number non è presente
         * nella SAML
         */
        if (attributes != null) {
            try {

                List<String> autoFedAttrValEidas = (List<String>) util.getAttributeVal(attributes, "spidCode");

                for (String val : autoFedAttrValEidas) {
                    if (val != null) {
                        userID = val.replace("/", "-");
                    }
                }

                logger.debug(method + "UserID: " + userID);

            } catch (Exception e) {
                logger.error(method + "Exception: ", e);
            }
        }

        if (userID != null) {
            // get user
            AMIdentity usrIdentity = null;
            List<AMIdentity> users = new ArrayList<AMIdentity>();

            users = repoUtil.getUserStoreIdentity(userID, realm);

            if (users != null && !users.isEmpty()) { // utente esistente
                // logger.debug(method + "_____users.size(): " + users.size());
                if (users.size() == 1) {
                    // logger.debug(method + "assegna l'unico utente trovato!!! ");
                    usrIdentity = users.get(0);
                } else {
                    SAML2Exception se = new SAML2Exception(
                            "Eccezione per name[" + userID + "] pi� di un utente con lo stesso codice fiscale");
                    throw se;
                }
            }

            // MODIFICA LOG EIDAS AZIENDE
            /**
             * Il flag flagCompany se è a false gestisce la logica Eidas Cittadino
             * Il flag flagCompany se è a true gestisce la logica Eidas Aziende
             */
            if (!flagCompany) {

                logger.debug(method + " GESTISCO EIDAS CITTADINO");

                if (usrIdentity != null) {

                    logger.debug(method + "usrIdentity is null");

                    /* CDM */
                    // aggiornare l'utente per update password ed inetuserstatus=Active
                    if (setCDMAttribute) {

                        logger.debug(method + "******* INIZIO Update Utente [" + usrIdentity.getName()
                                + "] setCDMAttribute CDM ********");

                        try {
                            Map<String, List<?>> userAttrMap = new HashMap<String, List<?>>();
                            /***
                             * aggiunta parametrizzazione per discriminare se aggiornare lo stato utente o
                             * meno
                             **/
                            if (updateCDMStatus) {

                                logger.debug(method + "******* Update Utente [" + usrIdentity.getName()
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

                                            logger.debug(method + "staticAttrName[" + arrayValue[0]
                                                    + "] staticAttrVal[" + arrayValue[1] + "]");
                                        }
                                    }
                                }
                            } else {

                                logger.debug(method + GLOBAL_PROP_UPDATEUSER_ATTRIBUTE
                                        + " undefined: NO user Attribute default set");
                            }

                            // password
                            userAttrMap.put(PWD_ATTR, Arrays.asList(setPassword()));

                            logger.debug(method + "******* FINE Update Utente [" + usrIdentity.getName()
                                    + "] setCDMAttribute CDM ********");

                            if (updateCDMUser) {
                                // nuova logica di update
                                try {
                                    userAttrMap = setUpdateUserAttrMap(map, attributes, userID, userAttrMap);
                                } catch (ParseException e) {
                                    e.printStackTrace();
                                }
                                if (!updateSPIDUsers(usrIdentity, userAttrMap, map)) {
                                    logger.error(method + "Errore aggiornamento utente [" + usrIdentity.getName()
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
                                    logger.error(method + "FEDERATION_FAILED_WRITING_ACCOUNT [" + usrIdentity.getName()
                                            + "]: errore scrittura UserStore");
                                    SAML2Exception se = new SAML2Exception(
                                            "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                    throw se;
                                } else {
                                    return userID;
                                }
                            }
                        } catch (SSOException | IdRepoException e) {
                            logger.error(method, e.getLocalizedMessage());
                            logger.error(method + "FEDERATION_FAILED_WRITING_ACCOUNT [" + usrIdentity.getName()
                                    + "]: errore scrittura UserStore");
                            SAML2Exception se = new SAML2Exception(
                                    "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                            throw se;
                        }
                    } else {
                        // se l'utente esiste ritorna l'accountID

                        logger.debug(method + "Utente [" + usrIdentity.getName()
                                + "] aggiornato - Federazione completata");

                    }

                    return usrIdentity.getName();
                } else if (createUserEnable) {

                    // CREA L'UTENTE IEDAS SULLO USER STORE

                    logger.debug(method + "******* INIZIO Creazione Cittadino EIDAS [" + userID + "]  ********");

                    if (createUserWs != null) {
                        /** richiama un WS di creazione utenza che si occupa anche dello UserStore **/
                        // TODO
                    } else {
                        /** crea l'utente sullo UserStore **/
                        Map<String, List<?>> attributeMap;
                        // ******* crea l'utente sullo userStore ********
                        try {
                            attributeMap = setUserAttrMap(map, attributes, userID);

                            // Aggiunta del codice fiscale fake
                            String codiceFiscaleFake = createFakeFiscalNumber(attributeMap, realm);

                            if (codiceFiscaleFake != null)
                                attributeMap.put("fiscalNumber", Arrays.asList(codiceFiscaleFake));

                            if (!repoUtil.addSpidUsers(userID, realm, null, userContainer, attributeMap)) {
                                logger.error(method + " utente [" + userID
                                        + "] FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                SAML2Exception se = new SAML2Exception(
                                        "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                                throw se;
                            } else {
                                // imposta il flag ad indicare che l'utenza � stata creata
                                // flagCreato();
                                logger.debug(method + "Utente [" + userID + "] creato - Federazione completata");
                                return userID;
                            }
                        } catch (SSOException | IdRepoException | ParseException e) {
                            logger.error(method, e.getLocalizedMessage());
                            logger.error(method + " utente [" + userID
                                    + "] FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                            SAML2Exception se = new SAML2Exception(
                                    "FEDERATION_FAILED_WRITING_ACCOUNT: errore scrittura UserStore");
                            throw se;
                        }
                    }
                }
            }
            // MODIIFCA LOG EIDAS AZIENDE
            else {

                logger.debug(method + " GESTISCO EIDAS COMPANY");
                SPIDEidasAziendeSpAccountMapper company = new SPIDEidasAziendeSpAccountMapper();
                return company.getIdentity(assertion, hostEntityID, realm);
            }
        }

        return null;

    }

    /**
     * Metodo che si occupa di popolare la mappa degli attributi utente da poi
     * memorizzare nello userstore.
     * 
     * @param attributeMap Attributi configurati per il mapper su AM
     * @param attributes   Attributi della SAML Assertion
     * @param userID       Identificativo dell'utente
     * @return Mappa degli attributi utente da memorizzare nello userstore
     * @throws ParseException
     */
    private Map<String, List<?>> setUserAttrMap(Map<String, List<String>> attributeMap, List<Attribute> attributes,
            String userID) throws ParseException {
        String method = "[setUserAttrMap]";

        logger.debug(method + "inizio ... ");

        Map<String, List<?>> userAttrMap = new HashMap<String, List<?>>();

        logger.debug(method + "******* INIZIO Iterator User [" + userID + "] - Attributi Asserzione ********");
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

                            logger.debug(method + "Attr Assertion MAP - fiscalNumber: "
                                    + codfisc.substring(TINSUFF.length()));
                        }
                        /*
                         * } else if (attribute.getName().equalsIgnoreCase("name") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         * } else if (attribute.getName().equalsIgnoreCase("familyName") &&
                         * attribute.getAttributeValueString() != null){
                         * userAttrMap.put(attribute.getName(), attribute.getAttributeValueString() );
                         */
                        // MODIFICA LOG EIDAS
                    } else if (attribute.getName().equalsIgnoreCase("spidCode")
                            && attribute.getAttributeValueString() != null) {
                        userAttrMap.put(attribute.getName(), attribute.getAttributeValueString());
                        /*
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
                         * 
                         * logger.debug(method + " -- (dataNascDate): " +
                         * attribute.getAttributeValueString() );
                         * Date dataNascDate =
                         * dateFormat.parse(getAttrAssertion(attribute.getAttributeValueString()));
                         * 
                         * logger.debug(method + " -- (dataNascDate): " + dataNascDate );
                         * String pattern = "yyyyMMdd000000";
                         * SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
                         * 
                         * logger.debug(method + "simpleDateFormat.format(dataNascDate): " +
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

                            logger.debug(
                                    method + "Generic Attr Assertion MAP - " + attrLDAP + " : " + attrLDAPVal);
                            userAttrMap.put(attrLDAP, Arrays.asList(attrLDAPVal));
                        }
                    }
                } // MODIFICA AGGIUNTA PER GESTIONE IDP POSTE
            }
        }

        logger.debug(method + "******* FINE Iterator User [" + userID + "] - Attributi Asserzione ********");

        /* CDM */
        if (setCDMAttribute) {

            logger.debug(method + "******* INIZIO setCDMAttribute User [" + userID + "] - Attributi CDM ********");

            // Gestione del campo cn
            if (userAttrMap.get("cn") != null)
                userAttrMap.remove("cn");
            String sNome = getAttrAssertion(util.getAttributeVal(attributes, "name"));
            String sCognome = getAttrAssertion(util.getAttributeVal(attributes, "familyName"));
            userAttrMap.put("cn", Arrays.asList(sNome + " " + sCognome));

            logger.debug(method + "cn [" + sNome + " " + sCognome + "]");

            // Gestione del campo cdmGiuridicaFisica.
            // cdmGiuridicaFisica impostata a F perchè si tratta di una persona giuridica
            userAttrMap.put(SPID_CDM_GIURIDICA_FISICA, Arrays.asList("F"));

            logger.debug(method + "cdmGiuridicaFisica [F]");

            // Gestione del campo cdmNascitaData
            if (getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")) != null &&
                    !getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")).isEmpty()) {
                DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
                String sdataNascDate = getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth"));

                logger.debug(method + "cdmNascitaData [ " + sdataNascDate + " ]");
                Date dataNascDate = dateFormat.parse(sdataNascDate);

                // cdmNascitaDataOld
                userAttrMap.put("cdmNascitaDataOld",
                        Arrays.asList(new SimpleDateFormat("yyyy-MM-dd").format(dataNascDate)));

                // cdmNascitaData
                userAttrMap.put("cdmNascitaData",
                        Arrays.asList(new SimpleDateFormat("yyyyMMdd000000").format(dataNascDate)));
            }

            // Gesstione del campo password
            userAttrMap.put(PWD_ATTR, Arrays.asList(setPassword()));

            logger.debug(method + "******* FINE setCDMAttribute User [" + userID + "] - Attributi CDM ********");
        }

        if (createUserAttr != null && !createUserAttr.isEmpty()) {

            logger.debug(
                    method + "******* INIZIO setCDMAttribute User [" + userID + "] - Attributi Statici ********");
            // se esistono attributi di default li imposta
            for (Map.Entry<String, String> entry : createUserAttr.entrySet()) {
                String defaultAttr = entry.getKey();
                String defaultAttrVal = entry.getValue();

                logger.debug(method + "defaultAttr[" + defaultAttr + "] defaultAttrVal[" + defaultAttrVal + "]");
                userAttrMap.put(defaultAttr, Arrays.asList(defaultAttrVal));
            }

            logger.debug(
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
        String method = "getAddressElement::";

        logger.debug(method + "--------  Address: " + sAddress + " ------------");
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

                        String sSt = sSplitAddress.substring(sSplitAddress.length() - 2);
                        mAddress.put("st", sSt);
                        {
                            logger.debug(method + "st[" + sSt + "]");
                            logger.debug(method + "postalCode[" + postalCode + "]");
                        }
                        return mAddress;
                    }
                }
            } catch (IndexOutOfBoundsException ex) {
                logger.error(method + ex.getLocalizedMessage());
            }
        }
        mAddress.put("default", sAddress); // se non si riesce a prasare ritorna la stringa originale
        return mAddress;
    }

    /*
     * Utility per impostazione password
     */
    private String setPassword() {
        // String method = "setPassword::";
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

    private static String getFirstNumber(String stringa) {
        Matcher m = Pattern.compile("[^0-9]*([0-9]+).*").matcher(stringa);
        if (m.matches()) {
            return m.group(1);
        }
        return null;
    }

    private static String getPostalCode(String stringa) {
        // String method = "getPostalCode:: ";
        Matcher m = Pattern.compile("[0-9]{5}").matcher(stringa);
        while (m.find()) {
            return m.group().toString();
        }
        return null;
    }

    private static String getStreetAddress(String stringa, String postalCode) {
        String method = "getStreetAddress::";
        int indice = stringa.indexOf(postalCode);
        if (indice > 0 && indice < stringa.length()) {
            String sStreet = stringa.substring(0, indice);
            logger.debug(method + "street[" + sStreet + "]");
            return sStreet.trim();
        } else
            return stringa;
    }

    /*
     * Partendo dal nome dell'attributo dell'asserzione recupera l'attributo ldap
     * corrispondente
     *
     */
    private String getCorrAttrLDAP(Map<String, List<String>> attributeMap, String assertionAttrName) {
        // String method = "[getCorrAttrLDAP]";
        // mappa gli attributi LDAP con quelli dell'asserzione
        for (Entry<String, List<String>> entry : attributeMap.entrySet()) {
            String assertionAttr = entry.getKey();
            List<String> luserAttr = entry.getValue();

            // if(debug.messageEnabled()){
            // logger.debug(method + "assertionAttr: " + assertionAttr );
            // logger.debug(method + "luserAttr: " + luserAttr );
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
     *
     */
    private List<String> getAllCorrAttrLDAP(Map<String, List<String>> attributeMap, String assertionAttrName) {
        String method = "[getAllCorrAttrLDAP]";
        // mappa gli attributi LDAP con quelli dell'asserzione
        for (Entry<String, List<String>> entry : attributeMap.entrySet()) {
            String assertionAttr = entry.getKey();
            List<String> luserAttr = entry.getValue();

            logger.debug(method + "assertionAttr: " + assertionAttr);
            logger.debug(method + "luserAttr: " + luserAttr);

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
                        // logger.debug(method + "[" + attribute.getName() + "]["+
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
            logger.error(method + "nullRealm");
            return null;
        }

        if (hostEntityID == null) {
            logger.error(method + "nullHostEntityID");
            return null;
        }

        SAML2MetaManager saml2MetaManager = SAML2Utils.getSAML2MetaManager();

        logger.debug(method + " DefaultAttrMapper: realm=" + realm + ", entity id=" +
                hostEntityID + ", role=" + role);

        try {
            Map<?, ?> attribConfig = null;
            IDPSSOConfigElement IDPSSOconfig = null;
            SPSSOConfigElement SPSSOconfig = null;
            if (role.equals(SAML2Constants.SP_ROLE)) {
                SPSSOconfig = saml2MetaManager.getSPSSOConfig(realm, hostEntityID);
                if (SPSSOconfig == null) {

                    logger.warn(method + "configuration is not defined.");

                    return Collections.emptyMap();
                }
                attribConfig = SAML2MetaUtils.getAttributes(SPSSOconfig);
            } else if (role.equals(SAML2Constants.IDP_ROLE)) {
                IDPSSOconfig = saml2MetaManager.getIDPSSOConfig(realm, hostEntityID);
                if (IDPSSOconfig == null) {
                    logger.warn(method + "configuration is not defined.");
                    return Collections.emptyMap();
                }
                attribConfig = SAML2MetaUtils.getAttributes(IDPSSOconfig);
            }

            List<?> mappedAttributes = (List<?>) attribConfig.get(SAML2Constants.ATTRIBUTE_MAP);

            if ((mappedAttributes == null) || (mappedAttributes.size() == 0)) {

                logger.debug(method +
                        "Attribute map is not defined for entity: " +
                        hostEntityID);

                return Collections.emptyMap();
            }
            Map<String, List<String>> map = new HashMap<String, List<String>>();

            for (Iterator<?> iter = mappedAttributes.iterator(); iter.hasNext();) {
                String entry = (String) iter.next();

                if (entry.indexOf("=") == -1) {

                    logger.debug(method + "Invalid entry." + entry);

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
            logger.error(method, sme);
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

        logger.debug(method + "parametri: usrIdentity[" + usrIdentity + "]");
        // logger.debug(method + "attributeMap [" + attributeMap + " ]");

        try {
            // aggiorna l'utente

            logger.debug(method + "inizio update utente SPID [" + usrIdentity.getName() + "]... ");

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
                    String userAttr = entry.getKey(); // attributo LDAP
                    Set<String> actualAttrVal = usrIdentity.getAttribute(userAttr); // valore attuale dell'attributo
                                                                                    // LDAP
                    if (entry.getValue() != null) { // valore del SAML da impostare
                        vals = new HashSet<String>();
                        Object[] userVals = entry.getValue().toArray();
                        String sVals = userVals[0].toString();
                        for (int i = 0; i < userVals.length; i++) {
                            if (userVals[i] != null && !userVals[i].toString().isEmpty())
                                vals.add((String) userVals[i]);
                        }

                        if (userAttr.equalsIgnoreCase("address") || userAttr.equalsIgnoreCase("street")
                                || userAttr.equalsIgnoreCase("st") || userAttr.equalsIgnoreCase("postalCode")) {
                            /* se cdmSIPOUpdated = false -> modificare anche address */
                            if (updateAddress) {

                                logger.debug(method + "updateAddress TRUE");
                                if (actualAttrVal != null && !actualAttrVal.isEmpty()) {
                                    for (String valore : actualAttrVal) {
                                        if (!valore.equals(sVals)) {
                                            updateIDMUser = true;
                                            // se sono diversi imposta l'attributo
                                            attrs.put(userAttr, vals);

                                            logger.debug(method + "userAttr[" + userAttr + "] actualAttrVal: "
                                                    + actualAttrVal.toString()
                                                    + " vals[ " + vals + "]");
                                        }
                                    }
                                } else {
                                    updateIDMUser = true;
                                    // se il valore attuale � null e quello SAML no lo imposta
                                    attrs.put(userAttr, vals);

                                    logger.debug(method + userAttr + ": " + vals);
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

                                                logger.debug(method + " updateIDMUser - sVals: " + sVals
                                                        + " actualAttrVal: " + actualVal);
                                                /*
                                                 * if( !sActualValueMobile.equalsIgnoreCase(sVals) ) {
                                                 * if(debug.messageEnabled())
                                                 * logger.debug(method + "sVals: " +sVals + " actualAttrVal: " +
                                                 * actualVal + " sActualValueMobile: " + sActualValueMobile );
                                                 * //se sono diversi o il mobile attuale o il mobile SPID imposta
                                                 * l'attributo SPID_MOBILE_ATTR ed il relativo flag
                                                 * flagMobileChanged();
                                                 * if(debug.messageEnabled())
                                                 * logger.debug(method + SPID_MOBILE_ATTR + ": " + vals +
                                                 * "flagMobileChanged: " + mobileChanged());
                                                 * }
                                                 */
                                            }
                                        } else {
                                            // se l'attuale mobile dell'utente e null imposta comunque lo
                                            // SPID_MOBILE_ATTR
                                            attrs.put(SPID_MOBILE_ATTR, vals);

                                            logger.debug(method + "set[" + SPID_MOBILE_ATTR
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

                                                logger.debug(method + " updateIDMUser - sVals: " + sVals
                                                        + " actualAttrVal: " + actualVal);
                                            }
                                            /*
                                             * if( !actualVal.equalsIgnoreCase(sVals) ){
                                             * if ( !sActualValueEmail.equalsIgnoreCase(sVals) ) {
                                             * if(debug.messageEnabled())
                                             * logger.debug(method + "sVals: " +sVals + " actualAttrVal: " + actualVal
                                             * + " sActualValueEmail: " + sActualValueEmail );
                                             * flagMailChanged();
                                             * if(debug.messageEnabled())
                                             * logger.debug(method + SPID_MAIL_ATTR + ": " + vals +
                                             * "flagMailChanged: "
                                             * + mailChanged());
                                             * }
                                             * }
                                             */
                                        } else {
                                            // se l'attuale email dell'utente e null imposta comunque lo SPID_MAIL_ATTR
                                            attrs.put(SPID_MAIL_ATTR, vals);

                                            logger.debug(method + "set[" + SPID_MAIL_ATTR
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

                                                logger.debug(method + "userAttr[" + userAttr + "] actualAttrVal: "
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

                                                logger.debug(method + userAttr + ": " + vals);
                                            }
                                        }
                                    }
                                    /*
                                     * if ( userAttr.equalsIgnoreCase(SPID_MAIL_ATTR) ) {
                                     * //se il valore del SAML � diverso dall'email attuale imposta il relativo flag
                                     * if(sActualValueEmail!=null){
                                     * if( !sActualValueEmail.equalsIgnoreCase(sVals) ) {
                                     * flagMailChanged();
                                     * if(debug.messageEnabled())
                                     * logger.debug(method + SPID_MAIL_ATTR + ": " + vals + "flagMailChanged: " +
                                     * mailChanged());
                                     * }
                                     * }
                                     * }
                                     * if ( userAttr.equalsIgnoreCase(SPID_MOBILE_ATTR) ){
                                     * if(sActualValueMobile!=null){
                                     * if( !sActualValueMobile.equalsIgnoreCase(sVals) ) {
                                     * //se il valore del SAML � diverso dal mobile attuale imposta il relativo flag
                                     * flagMobileChanged();
                                     * if(debug.messageEnabled())
                                     * logger.debug(method + SPID_MOBILE_ATTR + ": " + vals +
                                     * "flagMobileChanged: "
                                     * + mobileChanged());
                                     * }
                                     * }
                                     * }
                                     */
                                }
                            }
                        }
                    } else {
                        // se il valore del SAML � null

                        logger.debug(method + " valore Attributo SAML [" + userAttr + "] NULL ... ");
                        if (actualAttrVal != null && !actualAttrVal.isEmpty()) {
                            updateIDMUser = true;
                            // se il valore SAML � null ma l'attuale valore dell'attr non lo � lo svuota
                            attrs.put(userAttr, new HashSet<String>());

                            logger.debug(method + userAttr + " set VUOTO! ");
                        }
                    }
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
                            CustomEidasRestUtil restUtil;
                            try {
                                restUtil = new CustomEidasRestUtil(idmRestURL, idmRestURL_admin, idmRestURL_pwd);
                                if (restUtil.updateIDMUser(usrIdentity.getName(), attrs))
                                    logger.debug(method + " OK Chiamata REST IDM user[" + usrIdentity.getName()
                                            + "] Aggiornato");
                                else {
                                    logger.error(method + "ERRORE chiamata rest [" + idmRestURL + "]  IDM user["
                                            + usrIdentity.getName() + "]");
                                    // return false; //si � scelto di non interrompere l'accesso in caso di
                                    // eccezioni o errori nella chiamata REST
                                }
                            } catch (Exception e) {
                                logger.error(method + "ERRORE chiamata rest [" + idmRestURL + "] IDM user ["
                                        + usrIdentity.getName() + "]:: " + e.getMessage());
                            }
                        } else {

                            logger.debug(method + " aggiornamento IDM non effettuato per user["
                                    + usrIdentity.getName() + "]:: aggiornamento non necessario");
                        }
                    } else {

                        logger.debug(method + " chiamata rest IDM disabilitata per Base URL nullo o vuoto ");
                    }

                    return true;
                }
            } else
                logger.error(method + "Errore attributeMap NULL!!!");
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
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

        logger.debug(method + "inizio ... ");

        logger.debug(method + "******* INIZIO Iterator User [" + userID + "] - Attributi Asserzione ********");
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

                            logger.debug(method + "Attr Assertion MAP - fiscalNumber: "
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

                        logger.debug(method + " -- (" + SPID_MAIL_ATTR + "): " + sSpidEmail);
                        userAttrMap.put(SPID_MAIL_ATTR, Arrays.asList(sSpidEmail));
                    } else if (attribute.getName().equalsIgnoreCase("mobilePhone")
                            && attribute.getAttributeValueString() != null) {
                        // attributo SpidMobile
                        String sSpidMobile = getAttrAssertion(util.getAttributeVal(attributes, "mobilePhone"));

                        logger.debug(method + " -- (" + SPID_MOBILE_ATTR + "): " + sSpidMobile);
                        userAttrMap.put(SPID_MOBILE_ATTR, Arrays.asList(sSpidMobile));
                    } else {
                        List<String> lAttrLDAP = getAllCorrAttrLDAP(attributeMap, attribute.getName());
                        String attrLDAPVal = getAttrAssertion(attribute.getAttributeValueString());
                        if (lAttrLDAP != null) { // aggiunto
                            for (String attrLDAP : lAttrLDAP) {

                                logger.debug(
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
                        logger.debug(method + "Attr Assertion MAP - fiscalNumber: NULL !!!");
                    } else if (attribute.getName().equalsIgnoreCase(SPID_IVACODE_ATTRNAME)
                            && attribute.getAttributeValueString() != null) {
                        // TODO che fare in caso di Partira IVA NULL ...
                        userAttrMap.put(getCorrAttrLDAP(attributeMap, attribute.getName()), null);

                        logger.debug(method + "Attr Assertion MAP - " + SPID_IVACODE_ATTRNAME + ": NULL !!!");
                    } else if (attribute.getName().equalsIgnoreCase("email")
                            && attribute.getAttributeValueString() != null) {
                        // attributo SpidMail
                        userAttrMap.put(SPID_MAIL_ATTR, null);

                        logger.debug(method + " -- (" + SPID_MAIL_ATTR + "): NULL!!! ");
                    } else if (attribute.getName().equalsIgnoreCase("mobilePhone")
                            && attribute.getAttributeValueString() != null) {
                        // attributo SpidMobile
                        userAttrMap.put(SPID_MOBILE_ATTR, null);

                        logger.debug(method + " -- (" + SPID_MOBILE_ATTR + "): NULL!! ");
                    } else {
                        List<String> lAttrLDAP = getAllCorrAttrLDAP(attributeMap, attribute.getName());
                        for (String attrLDAP : lAttrLDAP) {

                            logger.debug(method + "Generic Attr Assertion MAP - " + attrLDAP + " : NULL!!");
                            userAttrMap.put(getCorrAttrLDAP(attributeMap, attribute.getName()), null);
                        }
                    }
                }
            }
        }

        logger.debug(method + "******* FINE Iterator User [" + userID + "] - Attributi Asserzione ********");

        /* CDM */
        if (setCDMAttribute) {

            logger.debug(method + "******* INIZIO setCDMAttribute User [" + userID + "] - Attributi CDM ********");
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
                } catch (IndexOutOfBoundsException ex) {
                    logger.error(method, ex.getLocalizedMessage());
                }
            }

            // aggiunto attributo cdmNascitaData
            if (getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")) != null &&
                    !getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth")).isEmpty()) {
                DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
                String sdataNascDate = getAttrAssertion(util.getAttributeVal(attributes, "dateOfBirth"));

                logger.debug(method + " -- (sdataNascDate): " + sdataNascDate);
                Date dataNascDate = dateFormat.parse(sdataNascDate);

                // cdmNascitaData
                userAttrMap.put("cdmNascitaData",
                        Arrays.asList(new SimpleDateFormat("yyyyMMdd000000").format(dataNascDate)));
            }

            logger.debug(method + "******* FINE setCDMAttribute User [" + userID + "] - Attributi CDM ********");
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

                    logger.debug(method + "rilevato cambio email, imposto mailChangedFlag a true ");
                    return "true";
                }
            } else if (ldapSPIDMailAttrVal == null && ldapMailAttrVal != null
                    && !assertionMailAttrVal.equalsIgnoreCase(ldapMailAttrVal)) {

                logger.debug(method + "ldapSPIDMailAttrVal null, imposto mailChangedFlag a true ");
                return "true";
            }
        } else {

            logger.debug(method + "attributo email non presente nell'asserzione ");
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

                    logger.debug(method + "rilevato cambio mobilePhone, imposto mobileChangedFlag a true ");
                    return "true";
                }
            } else if (ldapSPIDMobileAttrVal == null && ldapMobileAttrVal != null
                    && !assertionMobileAttrVal.replaceAll("^(\\+39|0039)", "")
                            .equalsIgnoreCase(ldapMobileAttrVal.replaceAll("^(\\+39|0039)", ""))) {

                logger.debug(method + "ldapSPIDMobileAttrVal null, imposto mobileChangedFlag a true ");
                return "true";
            }
        } else {

            logger.debug(method + "attributo mobilePhone non presente nell'asserzione ");
        }
        return "false";
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
                logger.error(method + "ldapDate is NULL");
            else
                logger.error(method + "errore durante il parsing di ldapDate");
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
     * @return HashMap<String, String> -> i valori dei 4 flags newCreationFlag,
     *         mailChangedFlag, mobileChangedFlag e newCreationknownFlag
     *         ed in caso oldMail e oldMobile che rappresentano i valori LDAP
     *         dell'account SPID pregresso
     */
    public HashMap<String, String> getPostLoginFlags(String realm, Response ssoResponse, String hostEntityID) {
        String method = "[getPostLoginFlags]:: ";

        logger.debug(method + "inizio ... ");

        // Inizializzo tutti i flags a false
        HashMap<String, String> postLoginFlags = new HashMap<String, String>(); // Mappa contenente i flags
        String newCreationFlag = "false";
        String mailChangedFlag = "false";
        String mobileChangedFlag = "false";
        String newCreationknownFlag = "false";
        String oldMail = null;
        String oldMobile = null;

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
                logger.error(method + "ssoResponse null o impossibile estrarre asserzione ");
            // Inserisco in una Lista gli attributi dell'attributeStatements dall'asserzione
            if (attributeStatements != null) {
                assertionAttributes = attributeStatements.get(0).getAttribute();
            } else
                logger.error(method + "attributeStatements null ");

            // Recupero l'attributo da utilizzare per la ricerca dell'utente
            if (assertionAttributes != null) {
                // Se l'autofederazione � attiva recupero l'attributo di autofederazione per
                // utilizzarlo nella ricerca utente
                String useAutoFed = getAttribute(realm, hostEntityID, SAML2Constants.AUTO_FED_ENABLED);
                if ((useAutoFed != null) && useAutoFed.equalsIgnoreCase("true")) {
                    // Recupero il nome dell'attributo
                    String autoFedAttr = getAttribute(realm, hostEntityID, SAML2Constants.AUTO_FED_ATTRIBUTE);

                    logger.debug(method + "attributo di auto federazione autoFedAttr: " + autoFedAttr);
                    if (autoFedAttr != null) {

                        logger.debug(method + "utilizzo l'attributo di auto federazione come UserID");
                        // Recupero il valore dell'attributo
                        userID = getAttrAssertion(util.getAttributeVal(assertionAttributes, autoFedAttr));
                        // Eseguo il substring nel caso inizi con il prefisso TINSUFF
                        if (userID != null && userID.startsWith(TINSUFF))
                            userID = userID.substring(TINSUFF.length());

                        logger.debug(method + "userID: " + userID);
                    } else
                        logger.error(method + "attributo di autofederazione NON definito.");
                } else { // Altrimenti utilizzo il nameID (se indicato nell'Entity Provider)
                    // Recupero il NameID dall'asserzione
                    NameID nameID = util.getNameID(assertion, hostEntityID, realm);
                    if (nameID != null && nameID.getValue() != null) {
                        // Controllo se nella configurazione dell'Entity Provider � indicato di
                        // utilizzare il NameID come UserID
                        String useNameID = getAttribute(realm, hostEntityID, SAML2Constants.USE_NAMEID_AS_SP_USERID);
                        if ((useNameID != null) && useNameID.equalsIgnoreCase("true")) {

                            logger.debug(method + "utilizzo NameID come UserID");
                            // Recupero il valore del nameID
                            userID = nameID.getValue().toUpperCase();
                            // Eseguo il substring nel caso inizi con il prefisso TINSUFF
                            if (userID != null && userID.startsWith(TINSUFF))
                                userID = userID.substring(TINSUFF.length());

                            logger.debug(method + "userID: " + userID);
                        } else
                            logger.error(method + "useNameID NULL or useNameID is FALSE : " + useNameID);
                    } else
                        logger.error(method + "NameID from assertion null ");
                }
            } else
                logger.error(method + "nessun attributo trovato nell'asserzione SAML ");

            // Eseguo la ricerca dell'utente
            if (userID != null && !userID.isEmpty()) {
                List<AMIdentity> users = repoUtil.getUserStoreIdentity(userID, realm);

                String assertionMailAttrVal = getAttrAssertion(util.getAttributeVal(assertionAttributes, "email")); // Attributo
                                                                                                                    // email
                                                                                                                    // dall'asserzione
                String assertionMobileAttrVal = getAttrAssertion(
                        util.getAttributeVal(assertionAttributes, "mobilePhone")); // Attributo mobile dall'asserzione

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
                        // console AM in eidas.searchuser.attribute
                        users = repoUtil.getUserStoreIdentityQueryAnd(searchFilter, realm);

                        // Se non trovo utenti pregressi innesco semplicemente il newCreationFlag a true
                        if (users == null || users.isEmpty()) {
                            newCreationFlag = "true";

                            logger.debug(method + "nessun utente trovato, imposto newCreationFlag a true");
                        } else {
                            // Altrimenti imposto il newCreationknownFlag a true
                            newCreationknownFlag = "true";

                            logger.debug(method
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

                                    logger.debug(method + "account pregresso " + user.getName().toString()
                                            + ", modifyTimestamp " + modifyTimestamp);

                                    Date ldapDate = parseLdapDate(modifyTimestamp);
                                    if (lastModifyTimestamp != null && ldapDate != null) {
                                        if (lastModifyTimestamp.compareTo(ldapDate) < 0) {
                                            lastModifyTimestamp = ldapDate;
                                            lastUserIdentity = user;

                                            logger.debug(method
                                                    + "lastModifyTimestamp � maggiore di ldapDate, per ora questo � l'utente pi� recente");
                                        } else {

                                            logger.debug(method
                                                    + "lastModifyTimestamp � minore di ldapDate, l'utente non � il pi� recente");
                                        }
                                    } else {
                                        lastUserIdentity = user;
                                        lastModifyTimestamp = ldapDate;

                                        logger.debug(method
                                                + "primo account ciclato, per ora considero questo come utente modificato pi� recentemente");
                                    }
                                }

                                logger.debug(method + "account pregresso pi� recente = "
                                        + lastUserIdentity.getName().toString());
                            } else {
                                // Altrimenti prendo l'unico utente rilevato
                                lastUserIdentity = users.get(0);

                                logger.debug(
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

                                logger.debug(
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

                                logger.debug(method
                                        + "rilevato mobileChangedFlag da account pregresso, imposto oldMobile = "
                                        + oldMobile);
                            }
                        }
                    } else { // Altrimenti imposto semplicemente newCreationFlag a true
                        newCreationFlag = "true";

                        logger.debug(method + "nessun utente trovato, imposto newCreationFlag a true");
                    }
                } else { // Altrimenti verifico se impostare a "true" i flags mailChangedFlag e
                         // mobileChangedFlag

                    AMIdentity userIdentity = users.get(0);
                    Map<String, List<String>> attrMap = getAttributeMap(hostEntityID, realm); // Mappa dei nomi degli
                                                                                              // attributi
                                                                                              // Asserzione=LDAP (presi
                                                                                              // da console AM)

                    logger.debug(method + "utente " + userIdentity.getName().toString() + " trovato ");

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
                }
            } else
                logger.error(method + "impossibile recuperare userID da asserzione");
        } catch (Exception e) {
            logger.error(method + "Exception: ", e);
        }
        postLoginFlags.put("newCreationFlag", newCreationFlag);
        postLoginFlags.put("mailChangedFlag", mailChangedFlag);
        postLoginFlags.put("mobileChangedFlag", mobileChangedFlag);
        // Gestione account pregressi
        postLoginFlags.put("newCreationknownFlag", newCreationknownFlag);
        postLoginFlags.put("oldMail", oldMail);
        postLoginFlags.put("oldMobile", oldMobile);

        logger.debug(method + "postLoginFlags: " + Arrays.asList(postLoginFlags));
        return postLoginFlags;
    }

    /**
     * Metodo per la creazione di un codice fiscale fittizio.
     * Si basa sugli attributi familyName e dateOfBirth presenti nella richiesta
     * SAML.
     * Viene fatta una ricerca sullo userstore per verificare se il codice fiscale
     * fittizio è già presente, in quel caso vien incrementato un suffisso per
     * evitare duplicati.
     * 
     * @param attributes Mappa degli attributi SAML.
     * @param realm      Il realm dell'utente da cercare sullo userstore.
     * @return Il codice fiscale fittizio creato.
     */
    private String createFakeFiscalNumber(Map<String, List<?>> attributes, String realm) {
        String method = "[createFakeFiscalNumber]:: ";

        logger.debug(method + "inizio nella creazione del fakeFiscalNumber...");

        String fakeFiscalNumber = null;

        // Prendo gli attributi necessari per la creazione del codice fiscale dalla
        // lista degli attributi SAML
        String familyName = (String) attributes.get("familyName").get(0);
        String dateOfBirth = (String) attributes.get("dateOfBirth").get(0);

        logger.debug(method + "familyName [" + familyName + "]  , dateOfBirth: [" + dateOfBirth + "]");

        // Parte di codice fiscale incrementale in caso di duplicati sullo userstore
        String incremental = "000";

        // Mappa per la conversione del mese di nascita per il codice fiscale
        Map<String, String> mapFiscalNumber = new HashMap<String, String>();
        mapFiscalNumber.put("GENNAIO", "A");
        mapFiscalNumber.put("FEBBRAIO", "B");
        mapFiscalNumber.put("MARZO", "C");
        mapFiscalNumber.put("APRILE", "D");
        mapFiscalNumber.put("MAGGIO", "E");
        mapFiscalNumber.put("GIUGNO", "H");
        mapFiscalNumber.put("LUGLIO", "L");
        mapFiscalNumber.put("AGOSTO", "M");
        mapFiscalNumber.put("SETTEMBRE", "P");
        mapFiscalNumber.put("OTTOBRE", "R");
        mapFiscalNumber.put("NOVEMBRE", "S");
        mapFiscalNumber.put("DICEMBRE", "T");

        // Controllo che gli attributi familyName e dateOfBirth non siano nulli
        if (familyName != null && dateOfBirth != null) {

            /*
             * Estrazione del mese di nascita dalla data di nascita e conversione in
             * italiano.
             * Il mese viene convertito in una lettera secondo la mappa mapFiscalNumber.
             */
            Month monthOfBirth = LocalDate.parse(dateOfBirth).getMonth();
            String mese = monthOfBirth.getDisplayName(java.time.format.TextStyle.FULL, java.util.Locale.ITALIAN);
            String meseCustom = null;
            for (Map.Entry<String, String> entry : mapFiscalNumber.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(mese))
                    meseCustom = entry.getValue();
            }

            logger.debug(method + "Lettera del mese da inserire nel codice fiscale [" + meseCustom + "]");

            /*
             * Estrazione del giorno di nascita.
             * Viene controllato se il giorno di nascita è inferiore a 10,questo perchè i
             * numeri con una cifra hanno bisogno dello zero davanti nel codice fiscale.
             */
            int dayOfBirth = LocalDate.parse(dateOfBirth).getDayOfMonth();
            String dayOfBirthString = null;

            if (dayOfBirth < 10) {
                dayOfBirthString = "0" + dayOfBirth;
            }

            logger.debug(method + "Giorno da inserire nel codice fiscale [" + dayOfBirthString + "]");

            /*
             * Estrazione dell'anno di nascita.
             * Viene preso l'anno dalla data di nascita e viene convertito in stringa e
             * vengono prese solo le ultime due cifre per il codice fiscale.
             */
            int yearOfBirth = LocalDate.parse(dateOfBirth).getYear();
            String yearOfBirthString = String.valueOf(yearOfBirth).substring(2, 4);

            logger.debug(method + "Anno da inserire nel codice fiscale [" + yearOfBirthString + "]");

            /*
             * Estrazione dal cognome solo le prime tre lettere per il codice fiscale.
             * Se il cognome ha meno di tre lettere, vengono aggiunte delle "X"
             */
            String cognomeCustom = familyName.substring(0, 3).toUpperCase();
            if (cognomeCustom.length() < 3) {
                StringBuilder sb = new StringBuilder(cognomeCustom);
                while (sb.length() < 3) {
                    sb.append("X");
                }
                cognomeCustom = sb.toString();
            } else if (cognomeCustom.length() > 3) {
                cognomeCustom = cognomeCustom.substring(0, 3);

            }

            logger.debug(method + "Cognome da inserire nel codice fiscale [" + cognomeCustom + "]");

            /*
             * Creazione del codice fiscale fittizio.
             * Il codice fiscale viene creato con la seguente struttura:
             * EID + cognomeCustom + yearOfBirthString + meseCustom + dayOfBirthString + "A"
             * + incremental + "Z"
             * Dove "EID" è un prefisso, "A" è un carattere fisso e "Z" è un suffisso.
             */
            fakeFiscalNumber = "EID" + cognomeCustom + yearOfBirthString + meseCustom + dayOfBirthString + "A"
                    + incremental + "Z";

            logger.debug(method + "fakeFiscalNumber: " + fakeFiscalNumber);

            // Ricerca nello userstore per verificare se il codice fiscale esiste già
            List<AMIdentity> users = new ArrayList<AMIdentity>();
            users = repoUtil.getUserStoreIdentity(fakeFiscalNumber, realm);

            if (users != null && !users.isEmpty()) {

                logger.debug(method + "Esiste già un codice fiscale uguale, ne creo uno nuovo");
                /*
                 * Incremento il valore dell'incrementale di 1 e lo aggiungo al codice fiscale,
                 * riconvertendolo in stringa.
                 * Con il metodo String.format("%03d", Integer.parseInt(incremental)) aggiungo
                 * gli zeri mancanti all'incrementale.
                 */
                incremental = String.valueOf(Integer.parseInt(incremental) + 1);
                String incrementalCustom = String.format("%03d", Integer.parseInt(incremental));
                fakeFiscalNumber = "EID" + cognomeCustom + yearOfBirthString + meseCustom + dayOfBirthString + "A"
                        + incrementalCustom + "Z";

                logger.debug(method + "fakeFiscalNumber nuovo [" + fakeFiscalNumber + "]");
            }

        } else {

            logger.debug(method + "familyName o dateOfBirth nulli");
            return null;
        }

        return fakeFiscalNumber;
    }

    // MODIFICA LOG EIDAS AZIENDE
    /**
     * @param attribute, parametro della SAML Request
     * @returns se il campo companyName è popolato allora si tratta di un accesso
     *          EIDAS AZIENDE e il flag viene messo a true(accesso EIDAS COMPANY)
     */
    private static Boolean checkCompany(Attribute attribute) {

        // Ciclo tutti i campi dell'attributo e controllo se è vuoto o popolato
        // Se fosse vuoto, sostituisco il carattere "-" per rendere il campo pulito
        for (int i = 0; i < attribute.getAttributeValueString().size(); i++) {

            String value = attribute.getAttributeValueString().get(i).toString();
            String valueNew = value.replaceAll("-", "");

            if (!valueNew.isEmpty())
                return true;
        }

        // for (String value : attribute.getAttributeValueString()) {
        //
        // String valueNew = value.replaceAll("-", "");
        //
        // if (!valueNew.isEmpty())
        // return true;
        // }
        return false;
    }

}
