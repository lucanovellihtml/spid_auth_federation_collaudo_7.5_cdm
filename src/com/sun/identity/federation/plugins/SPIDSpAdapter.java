package com.sun.identity.federation.plugins;

import java.io.PrintWriter;
import java.security.PrivateKey;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.*;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.common.SystemConfigurationUtil;
import com.sun.identity.custom.util.CustomFederationUtil;
import com.sun.identity.custom.util.CustomHandler;
import com.sun.identity.custom.util.CustomRepoUtil;
import com.sun.identity.custom.util.NameIDPolicyImplNoAllowCreate;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.saml.common.SAMLConstants;
import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.assertion.AttributeStatement;
import com.sun.identity.saml2.assertion.AuthnContext;
import com.sun.identity.saml2.assertion.AuthnStatement;
import com.sun.identity.saml2.assertion.EncryptedAssertion;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.jaxb.entityconfig.SPSSOConfigElement;
import com.sun.identity.saml2.key.KeyUtil;

import org.forgerock.openam.saml2.plugins.SPAdapter;

import com.sun.identity.saml2.plugins.SPIDSpAccountMapper;
import com.sun.identity.saml2.plugins.SPIDAziendeSpAccountMapper;
import com.sun.identity.saml2.protocol.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SPIDSpAdapter implements SPAdapter {

    /*
     * Regole di compilazione della console OpenAM:
     * aggiungere i seguenti attributi globali nelle advanced properties (Configure
     * > Server Defaults > Advanced)
     * - spid.idRepo : da specificare se esiste pi di un repository utente
     * (DataStore)
     * - spid.site.redirect: se specificato gestisce la redirect //aggiunto per
     * esposizione /fed openAM ex: https://sso.local.it/fed
     *
     * aggiungere i seguenti parametri nella definizione dell'SP della federazione
     * SPID
     * - "TRACCIATURE_KO" : (TRUE-FALSE) Ex: TRACCIATURE_KO=TRUE se si verifica un
     * errore in scrittura sul DB invalido l'accesso
     * - "HEADER_VARS" : Variabili ad-hoc per la federazione
     * - "HEADER_VALUE" : Ex: il testo con il quale verranno sovrascritte le var
     * header
     * - "REDIRECT_TO_ENABLE": (TRUE-FALSE) Ex: REDIRECT_TO_ENABLE=TRUE
     * - "REDIRECT_TO_GOTO" : (TRUE-FALSE) Ex: REDIRECT_TO_GOTO=TRUE (default FALSE)
     * - "FIRSTLOGIN_ATTRIBUTE": campo univoco LDAP per identificare first login
     * - "FIRSTLOGIN_ATTRIBUTE_VAL": valore per identificare first login
     * - "FIRSTLOGIN_LANDINGPAGE": pagina per primo accesso
     */

    private static Logger logger = null;
    private final static String DBGNAME = "SPIDSpAdapter";
    // private static final String TINSUFF = "TINIT-";

    // Istanza Logger di log4j 2, usata per loggare le transazioni SAML su file
    // dedicato, properties nel file
    // /opt/tomcat/webapps/openam/WEB-INF/classes/log4j2.xml
    public String transactionID = null;
    public boolean tracciatureFS = true;

    // add these attributes as advanced properties for FIRST LOGIN
    private static final String IDREPO = "spid.idRepo"; // Nome DataStore (es.: OpenDJ)
    private static final String GLOBAL_PROP_SITE_TO_REDIRECT = "spid.site.redirect";
    private static final String GLOBAL_PROP_CREATEUSER_BASEDN = "spid.createuser.enable.basedn";

    /* --- ATTRIBUTI DA CONFIGURARE DA CONSOLE -- */
    private final static String TRACCIATURE_KO = "TRACCIATURE_KO"; // (TRUE-FALSE) Ex: TRACCIATURE_KO=TRUE se si
                                                                   // verifica un errore in scrittura sul DB invalido
                                                                   // l'accesso
    private final static String TRACCIATURE_FS = "TRACCIATURE_FS"; // TRUE|FALSE
    private final static String HEADER_VARS_ATTR = "HEADER_VARS"; // Variabili ad-hoc per la federazione
    private final static String HEADER_VALUE_ATTR = "HEADER_VALUE"; // Ex: il testo con il quale verranno sovrascritte
                                                                    // le var header
    private final static String REDIRECT_TO_FIRSTLOGIN = "REDIRECT_TO_ENABLE"; // (TRUE-FALSE) Ex:
                                                                               // REDIRECT_TO_ENABLE=TRUE
    private final static String REDIRECT_TO_GOTO = "REDIRECT_TO_GOTO"; // (TRUE-FALSE) Ex: REDIRECT_TO_GOTO=TRUE
                                                                       // (default FALSE)
    private final static String PROP_FIRSTLOGIN_ATTRIBUTE = "FIRSTLOGIN_ATTRIBUTE"; // campo univoco LDAP per
                                                                                    // identificare first login
    private final static String PROP_FIRSTLOGIN_ATTRIBUTE_VALUE = "FIRSTLOGIN_ATTRIBUTE_VAL"; // valore per identificare
                                                                                              // first login
    private final static String PROP_FIRSTLOGIN_LANDINGPAGE = "FIRSTLOGIN_LANDINGPAGE"; // pagina per primo accesso
    // idsito NON NECESSARIO
    // private final static String PROP_HEADER_IDSITO = "HEADER_IDSITO"; // (Ex:
    // HEADER_IDSITO=IDSITO) se non definita non imposta l'header

    private final static String PROP_CREATEUSER_IDREPO = "CREATEUSER_IDREPO";
    private static String userContainer = null;

    public boolean tracciatureKo = false;
    public boolean redirectToFirstLogin = false;
    public boolean redirectToGoto = false;
    public boolean oauth2redAssertionEnable = false;
    public boolean choiceAuth = false;

    private Set<PrivateKey> recipientPrivateKey = null;

    public boolean oAuth2 = false;

    // Se abilitato il flag REDIRECT_TO_FIRSTLOGIN allora viene verificato
    // l'attributo ed il corrispettivo valore per stabilire se
    // si tratta di un primo accesso o meno. Di default viene stabilito che se non
    // vengono passati gli attributi a confronto per
    // il primo accesso viene considerato un primo accesso sempre e quindi fa sempre
    // la redirect
    private boolean primoAccesso = true; // TODO se si vuole impostare di default che non sia un primo accesso cambiare
                                         // a false
    private String HEADER_VARS_VAL = null;
    private String HEADER_VALUE = null;
    private HashMap<String, String> httpHeaderVarMap;

    private String FIRSTLOGIN_ATTRIBUTE = null;
    private String FIRSTLOGIN_ATTRIBUTE_VAL = null;
    private String FIRSTLOGIN_LANDINGPAGE = null;

    private String CREATEUSER_IDREPO = null;
    private String REDIRECT_TO = null;

    private final static String SPID_FISCALNUMBER_ATTRNAME = "fiscalNumber";

    private String newCreationFlag = "false";
    private String mailChangedFlag = "false";
    private String mobileChangedFlag = "false";

    // Flag aggiunto per la gestione del flusso toponomastica
    private String addressChangedFlag = "false";

    private String newCreationknownFlag = "false";
    private String oldMail = null;
    private String oldMobile = null;
    private String oldStreet = null;

    static CustomRepoUtil repoUtil = new CustomRepoUtil();
    static CustomFederationUtil util = new CustomFederationUtil();
    static SPIDSpAccountMapper<HashMap<String, String>> accountMapper = new SPIDSpAccountMapper<>();

    // MODIFICA LOG SPID AZIENDE
    // OGGETTO PER INNESCARE LA RICERCA DI UNA COMPANY PER L'AZIONE DI CREATE O
    // ACCESSO(UTENZA GIA' CREATA)
    static SPIDAziendeSpAccountMapper<HashMap<String, String>> accountMapperAziende = new SPIDAziendeSpAccountMapper<>();

    /**
     * Initializes the federation adapter, this method will only be executed
     * once after creation of the adapter instance.
     *
     * @param initParams initial set of parameters configured in the service
     *                   provider for this adapter. One of the parameters named
     *                   <code>HOSTED_ENTITY_ID</code> refers to the ID of this
     *                   hosted service provider entity, one of the parameters named
     *                   <code>REALM</code> refers to the realm of the hosted
     *                   entity.
     */
    @SuppressWarnings("rawtypes")
    public void initialize(Map initParams) {
        if (logger == null) {
            logger = LoggerFactory.getLogger(SPIDSpAdapter.class);
        }

        logger.debug(" ... initialize ... ");

        // default false
        if (initParams.get(TRACCIATURE_KO) != null)
            tracciatureKo = Boolean.parseBoolean((String) initParams.get(TRACCIATURE_KO));
        if (initParams.get(TRACCIATURE_FS) != null)
            tracciatureFS = Boolean.parseBoolean((String) initParams.get(TRACCIATURE_FS));
        if (initParams.get(REDIRECT_TO_FIRSTLOGIN) != null) {
            redirectToFirstLogin = Boolean.parseBoolean((String) initParams.get(REDIRECT_TO_FIRSTLOGIN));
        }
        if (initParams.get(REDIRECT_TO_GOTO) != null) {
            redirectToGoto = Boolean.parseBoolean((String) initParams.get(REDIRECT_TO_GOTO));
        }

        logger.debug("tracciatureKo: " + tracciatureKo);
        logger.debug("redirectToFirstLogin: " + redirectToFirstLogin);
        logger.debug("redirectToGoto: " + redirectToGoto);

        if (initParams.get(PROP_FIRSTLOGIN_ATTRIBUTE) != null)
            FIRSTLOGIN_ATTRIBUTE = (String) initParams.get(PROP_FIRSTLOGIN_ATTRIBUTE);
        if (initParams.get(PROP_FIRSTLOGIN_ATTRIBUTE_VALUE) != null)
            FIRSTLOGIN_ATTRIBUTE_VAL = (String) initParams.get(PROP_FIRSTLOGIN_ATTRIBUTE_VALUE);
        if (initParams.get(PROP_FIRSTLOGIN_LANDINGPAGE) != null)
            FIRSTLOGIN_LANDINGPAGE = (String) initParams.get(PROP_FIRSTLOGIN_LANDINGPAGE);

        if (initParams.get(PROP_CREATEUSER_IDREPO) != null)
            CREATEUSER_IDREPO = (String) initParams.get(PROP_CREATEUSER_IDREPO);

        userContainer = SystemProperties.get(GLOBAL_PROP_CREATEUSER_BASEDN);
        if (userContainer == null || userContainer.trim().equals("")) {

            logger.debug(GLOBAL_PROP_CREATEUSER_BASEDN + " undefined.");
        } else {

            logger.debug(GLOBAL_PROP_CREATEUSER_BASEDN + " value: " + userContainer);
        }

        if (initParams.get(HEADER_VARS_ATTR) != null)
            HEADER_VARS_VAL = (String) initParams.get(HEADER_VARS_ATTR);
        if (initParams.get(HEADER_VALUE_ATTR) != null)
            HEADER_VALUE = (String) initParams.get(HEADER_VALUE_ATTR);

        buildHttpHeaderVar(HEADER_VARS_VAL, HEADER_VALUE);

    }

    /**
     * Invokes before OpenSSO sends the
     * Single-Sing-On request to IDP.
     *
     * @param hostedEntityID entity ID for the hosted SP
     * @param idpEntityID    entity id for the IDP to which the request will
     *                       be sent. This will be null in ECP case.
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param authnRequest   the authentication request to be send to IDP
     * @throws SAML2Exception if user want to fail the process.
     */
    public void preSingleSignOnRequest(
            String hostedEntityID,
            String idpEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthnRequest authnRequest)
            throws SAML2Exception {
        String method = "[preSingleSignOnRequest]:: ";

        logger.debug(method + "inizio ... ");

        if (authnRequest != null) {
            authnRequest.setIsPassive(null); // add AM 6.5
            if (authnRequest.getIssuer() != null) {
                authnRequest.getIssuer().setNameQualifier(authnRequest.getIssuer().getValue());
                authnRequest.getIssuer().setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
            }
            if (authnRequest.getNameIDPolicy() != null) {
                authnRequest.getNameIDPolicy().setSPNameQualifier(null);
                // add AM 6.5
                // authnRequest.getNameIDPolicy().setAllowCreate(false);
                // com.sun.identity.custom.util.NameIDPolicyImplNoAllowCreate newNameIDPolicy =
                // (NameIDPolicyImplNoAllowCreate) authnRequest.getNameIDPolicy();
                com.sun.identity.custom.util.NameIDPolicyImplNoAllowCreate newNameIDPolicy = new NameIDPolicyImplNoAllowCreate();
                newNameIDPolicy.removeAllowCreate();
                newNameIDPolicy.setSPNameQualifier(null);
                newNameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

                authnRequest.setNameIDPolicy((NameIDPolicy) newNameIDPolicy);

            }

            // MODIFICA LOG SPID AZIENDE
            // CONTROLLO PER AGGIUNGERE ESTENSIONE ALLA SAML REQUEST PER UTENZA SOLO SPID
            // AZIENDE
            if (authnRequest.getAttributeConsumingServiceIndex() == 3) {
                // METODO PER AGGIUNGERE ESTENSIONE ALLA SAML REQUEST PER UTENZA SPID AZIENDE
                List extensionsList = getExtensionsList(hostedEntityID, realm);
                Extensions extensions = createExtensions(extensionsList);
                authnRequest.setExtensions(extensions);

                if (extensions != null) {
                    {
                        logger.debug("extensions: " + extensions.getAny());
                        logger.debug("authnRequest.getExtensions.getAny(): " + authnRequest.getExtensions().getAny());
                        // LOG PER STAMPARE INDEX DELLA SAML REQUEST
                        logger.debug("authnRequest.getAttributeConsumingServiceIndex(): "
                                + authnRequest.getAttributeConsumingServiceIndex());
                    }
                } else {
                    logger.error("extensions null");
                }
            }
        }
    }

    // MODIFICA LOG SPID AZIENDE
    // METODO PER CREA LA LISTA CON DENTRO L'ESTENSIONE
    private static Extensions createExtensions(List extensionsList) throws SAML2Exception {
        Extensions extensions = null;
        if (extensionsList != null && !extensionsList.isEmpty()) {
            extensions = ProtocolFactory.getInstance().createExtensions();
            extensions.setAny(extensionsList);
        }
        return extensions;
    }

    // MODIFICA LOG SPID AZIENDE
    // METODO PER INIZIALIZZARE L'ESTENSIONE
    public static List getExtensionsList(String entityID, String realm) {
        List<String> extensionsList = new ArrayList();
        extensionsList.add("<spid:Purpose xmlns:spid=\"https://spid.gov.it/saml-extensions\">PG</spid:Purpose>");
        return extensionsList;
    }

    /**
     * Invokes when the <code>FAM</code> received the Single-Sign-On response
     * from the IDP, this is called before any processing started on SP side.
     *
     * @param hostedEntityID entity ID for the hosted SP
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param authnRequest   the original authentication request sent from SP,
     *                       null if this is IDP initiated SSO.
     * @param ssoResponse    response from IDP
     * @param profile        protocol profile used, one of the following values:
     *                       <code>SAML2Constants.HTTP_POST</code>,
     *                       <code>SAML2Constants.HTTP_ARTIFACT</code>,
     *                       <code>SAML2Constants.PAOS</code>
     * @throws SAML2Exception if user want to fail the process.
     */
    public void preSingleSignOnProcess(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthnRequest authnRequest,
            Response ssoResponse,
            String profile)
            throws SAML2Exception {
        String method = "[preSingleSignOnProcess]:: ";

        logger.debug(method + "inizio ... ");

        // Recupero i flags per postLogin
        HashMap<String, String> postLoginFlags = new HashMap<String, String>();

        // MODIFICA LOG SPID AZIENDE
        /**
         * Controllo se dall'idp arriva il campo companyName per capire se si tratta di
         * un accesso company e mettere il flag a true e innescare la ricerca della
         * company sul DS
         * Ps. pulisco il valore dal "-" altrimenti viene contato come campo popolato
         * anche se non è popolato
         */
        Assertion assertion = null;
        List<AttributeStatement> attributeStatements = null;
        assertion = (Assertion) ssoResponse.getAssertion().get(0);
        attributeStatements = assertion.getAttributeStatements();

        Boolean flagSpidAziende = false;

        for (AttributeStatement val : attributeStatements) {
            for (Attribute attribute : val.getAttribute()) {
                String value = attribute.getAttributeValueString().get(0).replace("-", "");
                if (attribute.getName().contains("companyName") && !value.isEmpty())
                    flagSpidAziende = true;
            }
        }

        // MODIFICA LOG SPID AZIENDE
        /**
         * Controllo se avviare la challenge sull'utenza cittadino o company, questo
         * serve a capire se l'utenza ha già fatto un primo accesso o meno
         */
        if (!flagSpidAziende) {
            postLoginFlags = accountMapper.getPostLoginFlags(realm, ssoResponse, hostedEntityID);
        } else {
            postLoginFlags = accountMapperAziende.getPostLoginFlags(realm, ssoResponse, hostedEntityID);
        }

        newCreationFlag = postLoginFlags.get("newCreationFlag");
        mailChangedFlag = postLoginFlags.get("mailChangedFlag");
        mobileChangedFlag = postLoginFlags.get("mobileChangedFlag");
        newCreationknownFlag = postLoginFlags.get("newCreationknownFlag");
        oldMail = postLoginFlags.get("oldMail");
        oldMobile = postLoginFlags.get("oldMobile");
        oldStreet = postLoginFlags.get("oldStreet");
        // Flag aggiunto per la gestione del flusso toponomastica
        addressChangedFlag = postLoginFlags.get("addressChangedFlag");

        logger.debug(method + "recuperati postLoginFlags ");

        if (tracciatureFS) {
            if (authnRequest.getID() != null) {
                transactionID = authnRequest.getID();
            } else {
                logger.warn(method + "Impossibile recuperare Authn_ID dalla request.");
                transactionID = UUID.randomUUID().toString();
            }
            logger.info("| [transactionID= " + transactionID + "] | authnRequest= "
                    + authnRequest.toXMLString().replaceAll("(\\r|\\n)", "")); // Intera authnRequest loggata in una
                                                                               // riga da sola
        }

    }

    /**
     * Invokes after Single-Sign-On processing succeeded.
     *
     * @param hostedEntityID Entity ID for the hosted SP
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param out            the print writer for writing out presentation
     * @param session        user's session
     * @param authnRequest   the original authentication request sent from SP,
     *                       null if this is IDP initiated SSO.
     * @param ssoResponse    response from IDP
     * @param profile        protocol profile used, one of the following values:
     *                       <code>SAML2Constants.HTTP_POST</code>,
     *                       <code>SAML2Constants.HTTP_ARTIFACT</code>,
     *                       <code>SAML2Constants.PAOS</code>
     * @param isFederation   true if this is federation case, false otherwise.
     * @return true if browser redirection happened after processing,
     *         false otherwise. Default to false.
     * @throws SAML2Exception if user want to fail the process.
     */
    public boolean postSingleSignOnSuccess(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            PrintWriter out,
            Object session,
            AuthnRequest authnRequest,
            Response ssoResponse,
            String profile,
            boolean isFederation)
            throws SAML2Exception {
        String method = "[postSingleSignOnSuccess]:: ";

        logger.debug(method + "inizio");

        // GET KEY ALTERNATIVA
        if (recipientPrivateKey == null) {
            try {
                SPSSOConfigElement spssoconfig = SAML2Utils.getSAML2MetaManager().getSPSSOConfig(realm, hostedEntityID);
                if (spssoconfig != null)
                    recipientPrivateKey = (Set<PrivateKey>) KeyUtil.getDecryptionKeys(spssoconfig);
                else
                    logger.error("Errore GET KEY ALTERNATIVA: spssoconfig NULL ");
                // nameID = encryptedID.decrypt(decryptionKey);
            } catch (Exception e) {
                logger.error("Errore GET KEY ALTERNATIVA: ", e);
                e.printStackTrace();
            }
        }

        logger.debug("tracciatureFS: " + tracciatureFS);
        logger.debug("tracciatureKo: " + tracciatureKo);
        logger.debug("redirectToFirstLogin: " + redirectToFirstLogin);
        logger.debug("redirectToGoto: " + redirectToGoto);

        Assertion assertion = getAssertionSpid(ssoResponse);
        if (assertion == null) {
            SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
            invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                    authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
            throw se;
        }

        if (!tracciatureKo) {
            if (!writeRecordSpid(assertion, authnRequest, ssoResponse)) {
                SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
                invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                        authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
                throw se;
            }
        }

        if (tracciatureFS) {
            if (!writeRecordFS(assertion, authnRequest, ssoResponse)) {
                SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
                invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                        authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
                throw se;
            }
        }

        SSOToken ssoToken = (SSOToken) session;

        /*
         * Gestione utenze SPID pregresse, se nuovo utente con altro account pregresso
         * ha cambiato mail/mobile
         * allora eseguo update del nuovo account con i valori dell'account pregresso e
         * innesco la challenge mobile/mail-changed
         */
        Map<String, List<?>> userAttributeMap = new HashMap<String, List<?>>();
        if (oldMail != null) {
            String[] arrayOldMail = oldMail.split("=");
            userAttributeMap.put(arrayOldMail[0], Arrays.asList(arrayOldMail[1]));

            logger.debug(method + "oldMail = " + oldMail);
        }
        if (oldMobile != null) {
            String[] arrayOldMobile = oldMobile.split("=");
            userAttributeMap.put(arrayOldMobile[0], Arrays.asList(arrayOldMobile[1]));

            logger.debug(method + "oldMobile = " + oldMobile);
        }

        // Eseguo update utente solo se oldMail o oldMobile sono stati rilevati
        try {
            if (userAttributeMap.size() > 0 && ssoToken != null && ssoToken.getPrincipal().getName() != null) {

                logger.debug(method + "userAttributeMap = " + userAttributeMap);

                String accountName = null;
                String[] accountNameArray = ssoToken.getPrincipal().getName().split(",");
                if (accountNameArray != null) {
                    int i = accountNameArray[0].indexOf("=");
                    accountName = accountNameArray[0].substring(i + 1);
                }
                if (accountName != null && !accountName.isEmpty()) {

                    List<AMIdentity> users = repoUtil.getUserStoreIdentity(accountName, realm);

                    logger.debug(method + "UTENZA[" + accountName + "] e realm[" + realm + "]");
                    logger.debug(method + "UTENZA[" + users + "]");

                    if (users != null && !users.isEmpty()) {
                        if (users.size() > 1) {
                            logger.debug(method + "trovate piu occorrenze sullo UserStore per name[" + accountName
                                    + "] e realm[" + realm + "]");
                        } else {
                            AMIdentity user = users.get(0);
                            if (user != null) {
                                repoUtil.updateSpidUsers(user, userAttributeMap);

                                logger.debug(method + "rilevato utente " + accountName
                                        + " LDAP da aggiornare con i seguenti attributi: " + userAttributeMap);
                            }
                        }
                    } else {
                        logger.error(method + "utente " + accountName + " non trovato");
                    }
                } else {
                    logger.error(method + "accountName NULL");
                }
            }
        } catch (Exception ex) {
            logger.error(method
                    + " Eccezione durante l'update del nuovo utente con mail/mobile dell'utente SPID pregresso: " + ex);
        }

        // Aggiunta modifica per livello di autenticazione SPID - INIZIO
        /****
         * modificato per prendere la variabile SPID_LEVEL dalla Responce e non dalla
         * Request inquanto potrebbero differire
         ****/
        // RequestedAuthnContext authnContext = authnRequest.getRequestedAuthnContext();
        if (assertion.getAuthnStatements() != null && assertion.getAuthnStatements().size() >= 1) {
            AuthnStatement authnState = assertion.getAuthnStatements().get(0);
            AuthnContext authnContext = authnState.getAuthnContext();
            /*** fine modifica ***/
            try {
                // valorizazione variabile header per livello di autenticazione SPID
                // https://www.spid.gov.it/SpidL1
                if (authnContext.getAuthnContextClassRef() != null) {
                    String authnCtx = authnContext.getAuthnContextClassRef().toString();
                    // authnCtx= authnCtx.substring(1, authnCtx.length()-1);
                    authnCtx = authnCtx.substring(1, authnCtx.length());
                    String[] SpidLevel = authnCtx.split(":");

                    logger.debug(method + "SpidLevel[SpidLevel.length-1] : " + SpidLevel[SpidLevel.length - 1]);
                    String livelloSPID = SpidLevel[SpidLevel.length - 1]
                            .substring(SpidLevel[SpidLevel.length - 1].indexOf("www"));
                    ssoToken.setProperty("HTTP_SPID_LEVEL", livelloSPID);

                    logger.debug(method + "HTTP_SPID_LEVEL: " + livelloSPID);
                } else
                    logger.error(method
                            + "Errore impostazione variabili header HTTP_SPID_LEVEL: Errore in lettura Authn context");
            } catch (SSOException e1) {
                logger.error(method + "Errore impostazione variabili header HTTP_SPID_LEVEL", e1);
                SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
                invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                        authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
                throw se;
            }
        }
        // Aggiunta modifica per livello di autenticazione SPID - FINE

        // Aggiunta modifica per IMPOSTAZIONE FLAG Iv-newCreation - INIZIO
        try {
            ssoToken.setProperty("HTTP_Iv-newCreation", newCreationFlag);

            logger.debug(method + "HTTP_Iv-newCreation: " + newCreationFlag);

        } catch (SSOException e) {
            logger.error(method + "Errore impostazione variabili header HTTP_Iv-newCreation", e);
            SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
            invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                    authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
            throw se;
        }
        // Aggiunta modifica per IMPOSTAZIONE FLAG Iv-newCreation - FINE

        // Aggiunta modifica per IMPOSTAZIONE FLAG spidmobilechanged - INIZIO
        /*
         * In caso di variazione, dovr essere propagato in HTTP header insieme al
         * relativo flag di controllo ( spidmobilechanged )
         */
        try {
            ssoToken.setProperty("HTTP_spidmobilechanged", mobileChangedFlag);

            logger.debug(method + "HTTP_spidmobilechanged: " + mobileChangedFlag);

        } catch (SSOException e) {
            logger.error(method + "Errore impostazione variabili header HTTP_spidmobilechanged", e);
            SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
            invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                    authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
            throw se;
        }
        // Aggiunta modifica per IMPOSTAZIONE FLAG spidmobilechanged - FINE

        // Aggiunta modifica per IMPOSTAZIONE FLAG HTTP_spidaddresschanged - INIZIO
        // In caso di variazione dell'address dovrà essere propagato in HTTP header il
        // relativo flag di controllo ( HTTP_spidaddresschanged )
        try {
            ssoToken.setProperty("HTTP_spidaddresschanged", addressChangedFlag);

            logger.debug(method + "HTTP_spidaddresschanged: " + addressChangedFlag);

        } catch (SSOException e) {
            logger.error(method + "Errore impostazione variabili header HTTP_spidaddresschanged", e);
            SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
            invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                    authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
            throw se;
        }
        // Aggiunta modifica per IMPOSTAZIONE FLAG HTTP_spidaddresschanged - FINE

        // Aggiunta modifica per IMPOSTAZIONE FLAG HTTP_spidemailchanged - INIZIO
        /*
         * In caso di variazione dell'email dovr essere propagato in HTTP header il
         * relativo flag di controllo ( spidemailchanged )
         */
        try {
            ssoToken.setProperty("HTTP_spidemailchanged", mailChangedFlag);

            logger.debug(method + "HTTP_spidemailchanged: " + mailChangedFlag);

        } catch (SSOException e) {
            logger.error(method + "Errore impostazione variabili header HTTP_spidemailchanged", e);
            SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
            invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                    authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
            throw se;
        }
        // Aggiunta modifica per IMPOSTAZIONE FLAG HTTP_spidemailchanged - FINE

        // Aggiunta modifica per IMPOSTAZIONE FLAG Iv-newCreationknown - INIZIO
        try {
            ssoToken.setProperty("HTTP_Iv-newCreationknown", newCreationknownFlag);

            logger.debug(method + "HTTP_Iv-newCreationknown: " + newCreationknownFlag);

        } catch (SSOException e) {
            logger.error(method + "Errore impostazione variabili header HTTP_Iv-newCreationknown", e);
            SAML2Exception se = new SAML2Exception("SSO_FAILED_SESSION_ERROR");
            invokeSPAdapterForSSOFailure(hostedEntityID, realm, request, response,
                    authnRequest, ssoResponse, profile, SPAdapter.SSO_FAILED_SESSION_ERROR, se);
            throw se;
        }
        // Aggiunta modifica per IMPOSTAZIONE FLAG Iv-newCreationknown - FINE

        // gestione redirect alla pagina configurata da console ...
        if (redirectToFirstLogin) {
            boolean isFirstLogin = isFirstLogin(ssoToken, realm);

            logger.debug(method + "redirect alla pagina di PRIMO ACCESSO: " + redirectToFirstLogin);
            logger.debug(method + "redirect alla pagina - isFirstLogin: " + isFirstLogin);

            if (isFirstLogin)
                return redirectToFirstLogin(ssoToken, realm, response);
        }

        // gestione redirect alla pagina chiamante ... probabilmente non serve

        logger.debug(method + "redirect alla pagina chiamante: " + redirectToGoto);
        if (redirectToGoto && REDIRECT_TO != null) {
            return sendRedirect(response, REDIRECT_TO, null);
        }

        return false;
    }

    // invoke SPAdapter for failure
    private static void invokeSPAdapterForSSOFailure(
            String hostEntityId,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthnRequest authnRequest,
            Response respInfo,
            String profile,
            int errorCode,
            SAML2Exception se) {
        String method = "[invokeSPAdapterForSSOFailure]:: ";

        logger.debug(method + "inizio ... ");

        SPAdapter spAdapter = null;
        try {
            spAdapter = SAML2Utils.getSPAdapter(hostEntityId, realm);
        } catch (SAML2Exception e) {

            logger.debug(method, e);

        }
        if (spAdapter != null) {
            boolean redirected = spAdapter.postSingleSignOnFailure(
                    hostEntityId, realm, request, response, authnRequest,
                    respInfo, profile, errorCode);
            se.setRedirectionDone(redirected);
        }
    }

    /**
     * Invokes after Single Sign-On processing failed.
     *
     * @param hostedEntityID Entity ID for the hosted SP
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param authnRequest   the original authentication request sent from SP,
     *                       null if this is IDP initiated SSO.
     * @param ssoResponse    response from IDP
     * @param profile        protocol profile used, one of the following values:
     *                       <code>SAML2Constants.HTTP_POST</code>,
     *                       <code>SAML2Constants.HTTP_ARTIFACT</code>,
     *                       <code>SAML2Constants.PAOS</code>
     * @param failureCode    an integer specifies the failure code. Possible
     *                       failure codes are defined in this interface.
     * @return true if browser redirection happened, false otherwise. Default to
     *         false.
     */
    public boolean postSingleSignOnFailure(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthnRequest authnRequest,
            Response ssoResponse,
            String profile,
            int failureCode) {

        String method = "[postSingleSignOnFailure]:: ";

        logger.debug(method + "inizio");
        logger.debug(method + "failureCode: " + failureCode);
        logger.debug(
                method + "ERROR_PAGE_URL:" + SystemConfigurationUtil.getProperty(SAMLConstants.ERROR_PAGE_URL));

        Assertion assertion = getAssertionSpid(ssoResponse);

        // scrittura record sul DB per errore federazione
        if (!tracciatureKo) {
            if (!writeRecordSpid(assertion, authnRequest, ssoResponse)) {
                failureCode = SPAdapter.SSO_FAILED_SESSION_ERROR;
            }
        }

        Status status = ssoResponse.getStatus();

        // richiama la pagin di errore
        response.setContentType("text/html");

        // modifica per esposizione openMA /fed - INIZIO
        // get advanced properties
        String siteToRedirect = SystemProperties.get(GLOBAL_PROP_SITE_TO_REDIRECT);
        if (siteToRedirect == null || siteToRedirect.trim().equals("")) {
            // se non impostata la variabile globale allora va sul context path come prima
            siteToRedirect = request.getContextPath();

            logger.debug(GLOBAL_PROP_SITE_TO_REDIRECT + " undefined: use default value context path");
        } else {

            logger.debug(GLOBAL_PROP_SITE_TO_REDIRECT + " value: " + siteToRedirect);
        }
        StringBuffer site = new StringBuffer(siteToRedirect);
        // modifica per esposizione openMA /fed - FINE

        site.append("/spidError.jsp?failurecode=");
        site.append(failureCode);
        if (status != null && status.getStatusMessage() != null) {
            site.append("&statuscode=");
            site.append(status.getStatusMessage());
        }

        // if (failureCode == SPAdapter.SSO_FAILED_NO_USER_MAPPING) {
        response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
        response.setHeader("Location", site.toString());

        logger.debug(method + "redirect to ... " + site.toString());

        return true;
    }

    /**
     * Invokes after new Name Identifier processing succeeded.
     *
     * @param hostedEntityID Entity ID for the hosted SP
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param userID         Universal ID of the user with whom the new name
     *                       identifier
     *                       request performed
     * @param idRequest      New name identifier request, value will be
     *                       null if the request object is not available
     * @param idResponse     New name identifier response, value will be
     *                       null if the response object is not available
     * @param binding        Binding used for new name identifier request,
     *                       one of following values:
     *                       <code>SAML2Constants.SOAP</code>,
     *                       <code>SAML2Constants.HTTP_REDIRECT</code>
     */
    public void postNewNameIDSuccess(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            String userID,
            ManageNameIDRequest idRequest,
            ManageNameIDResponse idResponse,
            String binding) {
        return;
    }

    /**
     * Invokes after Terminate Name Identifier processing succeeded.
     *
     * @param hostedEntityID Entity ID for the hosted SP
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param userID         Universal ID of the user with whom name id termination
     *                       performed.
     * @param idRequest      Terminate name identifier request.
     * @param idResponse     Terminate name identifier response, value will be
     *                       null if the response object is not available
     * @param binding        binding used for Terminate Name Identifier request,
     *                       one of following values:
     *                       <code>SAML2Constants.SOAP</code>,
     *                       <code>SAML2Constants.HTTP_REDIRECT</code>
     */
    public void postTerminateNameIDSuccess(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            String userID,
            ManageNameIDRequest idRequest,
            ManageNameIDResponse idResponse,
            String binding) {
        return;
    }

    /**
     * Invokes before single logout process started on <code>SP</code> side.
     * This method is called before the user session is invalidated on the
     * service provider side.
     *
     * @param hostedEntityID Entity ID for the hosted SP
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param userID         universal ID of the user
     * @param logoutRequest  single logout request object
     * @param logoutResponse single logout response, value will be
     *                       null if the response object is not available
     * @param binding        binding used for Single Logout request,
     *                       one of following values:
     *                       <code>SAML2Constants.SOAP</code>,
     *                       <code>SAML2Constants.HTTP_REDIRECT</code>
     * @throws SAML2Exception if user want to fail the process.
     */
    public void preSingleLogoutProcess(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            String userID,
            LogoutRequest logoutRequest,
            LogoutResponse logoutResponse,
            String binding)
            throws SAML2Exception {
        // TODO - da aggiungere per Single Logout SPID - da testare
        String method = "[preSingleLogoutProcess]:: ";

        logger.debug(method + "inizio ... ");

        if (logoutRequest != null) {
            if (logoutRequest.getIssuer() != null) {
                logoutRequest.getIssuer().setNameQualifier(logoutRequest.getIssuer().getValue());
                logoutRequest.getIssuer().setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
            }
        }

        return;
    }

    /**
     * Invokes after single logout process succeeded, i.e. user session
     * has been invalidated.
     *
     * @param hostedEntityID Entity ID for the hosted SP
     * @param realm          Realm of the hosted SP.
     * @param request        servlet request
     * @param response       servlet response
     * @param userID         universal ID of the user
     * @param logoutRequest  single logout request, value will be
     *                       null if the request object is not available
     * @param logoutResponse single logout response, value will be
     *                       null if the response object is not available
     * @param binding        binding used for Single Logout request,
     *                       one of following values:
     *                       <code>SAML2Constants.SOAP</code>,
     *                       <code>SAML2Constants.HTTP_REDIRECT</code>
     */
    public void postSingleLogoutSuccess(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            String userID,
            LogoutRequest logoutRequest,
            LogoutResponse logoutResponse,
            String binding) {
        return;
    }

    private String getAdvancedProperty(String propertyName) {
        String method = "[getAdvancedProperty]:: ";

        String result = SystemProperties.get(propertyName);
        if (result == null) {
            result = "";
        } else {
            result = result.trim();
        }
        if (result.equals("")) {

            logger.debug(method + " Conf " + propertyName + " undefined.");
            // logger.error(method + " You need to define these Advanced Properties: " +
            // ADVANCED_ATTRIBUTE + "\n "
            // + ADVANCED_ATTRIBUTE_VALUE + "\n " + ADVANCED_LANDINGPAGE );

        } else {

            logger.debug(method + " Conf " + propertyName + "=" + result);

        }
        return result;
    }

    private boolean sendRedirect(HttpServletResponse response, String urlToRedirect, Map<String, String> queryString) {
        String method = "[sendRedirect]:: ";

        if (urlToRedirect == null)
            return false;

        if (queryString != null) {
            StringBuffer url = new StringBuffer(urlToRedirect);
            // logger.debug(method + "PRE url: " + url.toString());
            if (!url.toString().endsWith("?") && !url.toString().contains("?"))
                url.append("?");
            for (Entry<String, String> ele : queryString.entrySet()) {
                if (!url.toString().endsWith("?") || !url.toString().endsWith("&"))
                    url.append("&");
                url.append(ele.getKey());
                url.append("=");
                url.append(ele.getValue());
            }
            urlToRedirect = url.toString();
        }

        // richiama la pagin di errore
        response.setContentType("text/html");
        response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
        response.setHeader("Location", urlToRedirect.toString());

        logger.debug(method + "redirect to ... " + urlToRedirect);

        return true;
    }

    private void buildHttpHeaderVar(String httpParams, String value) {
        String method = "[buildHttpHeaderVar]:: ";

        if (httpParams != null || value != null) {

            logger.debug(method + "httpParams: " + httpParams);

            if (httpParams.indexOf(";") != -1) {
                String[] array_parametri = httpParams.split(";");
                if (array_parametri != null) {
                    httpHeaderVarMap = new HashMap<String, String>();
                    for (int i = 0; i < array_parametri.length; i++) {
                        if (array_parametri[i] != null) {
                            httpHeaderVarMap.put(array_parametri[i], value);
                            // httpHeaderVarMap.put(array_parametri[i], value);
                            // String[] parametro = array_parametri[i].split(",");
                            // if( parametro!=null && parametro[0]!=null && parametro[1]!=null ){
                            // httpHeaderVarMap.put(parametro[0], parametro[1]);
                            // logger.debug( method + "parametro[0]: " + parametro[0] );
                            // logger.debug( method + "parametro[1]: " + parametro[1] );
                            //
                            // }
                        } else
                            logger.error(method + "errore valorizzazioni HEADER. httpParams[" + httpParams + "]");
                    }
                }
            } else {
                httpHeaderVarMap.put(httpParams, value);
            }
        } else
            logger.debug(method + "valorizzazioni HEADER: parametri in input nulli");
    }

    private Assertion getAssertionSpid(Response ssoResponse) {
        String method = "[getAssertionSpid]:: ";

        logger.debug(method + "inizio ... ");

        // GET ASSERTION
        List<?> asserts;
        Assertion assertion = null;
        EncryptedAssertion encryptedAssertion;
        try {
            asserts = ssoResponse.getAssertion();
            assertion = (Assertion) asserts.get(0);
        } catch (Exception e) {

            logger.debug(method + "Assertion cifrata!!!");
            try {
                // ALLORA E\' CIFRATA
                asserts = ssoResponse.getEncryptedAssertion();
                if (recipientPrivateKey != null && asserts != null && asserts.get(0) != null) {
                    encryptedAssertion = (EncryptedAssertion) asserts.get(0);
                    assertion = encryptedAssertion.decrypt(recipientPrivateKey);
                } else {
                    logger.error(method + "ID [" + ssoResponse.getID() + "] Issuer [" + ssoResponse.getIssuer()
                            + "] Message: ERRORE nella decriptazione dell'asserzione: asserts nulla.");
                    return null;
                }
            } catch (Exception ex) {
                logger.error(method + "ID [" + ssoResponse.getID() + "] Issuer [" + ssoResponse.getIssuer()
                        + "] Message: ERRORE nella decriptazione dell'asserzione.");
                ex.printStackTrace();
                return null;
            }
        }

        logger.debug(method + " ... fine");
        return assertion;
    }

    private boolean writeRecordFS(Assertion assertion, AuthnRequest authnRequest,
            Response ssoResponse) {
        // E' presente una loggata al di fuori di questo metodo, nel metodo
        // preSingleSignOnProcess, dove logga solo l'intera authnRequest
        String method = "[writeRecordFS]:: ";

        logger.debug(method + "inizio ... ");

        /*
         * TRACCIATURE SERVICE PROVIDER
         * - <AuthnRequest>;
         * - <Response>;
         * - AuthnReq_ID;
         * - AuthnReq_ IssueInstant;
         * - InResponseTo;
         * - Resp_ID;
         * - Resp_ IssueInstant;
         * - Resp _ Issuer;
         * - Assertion_ID;
         * - Assertion_subject;
         * - Assertion_subject_NameQualifier;
         */
        Map<String, Object> log_value = new HashMap<String, Object>();

        try {
            if (authnRequest != null) {
                if (authnRequest.getID() != null) {

                    logger.debug(method + "AuthnReq_ID: " + authnRequest.getID());
                    log_value.put("AuthnReq_ID", authnRequest.getID()); // String
                } else {

                    logger.debug(method + "AuthnReq_ID: null ... ");
                }

                if (authnRequest.getIssueInstant() != null) {

                    logger.debug(method + "AuthnReq_IssueInstant: " + authnRequest.getIssueInstant().toString());
                    log_value.put("AuthnReq_IssueInstant", new Timestamp(authnRequest.getIssueInstant().getTime())); // Timestamp
                } else {

                    logger.debug(method + "AuthnReq_IssueInstant: null ... ");
                }
            } else {

                logger.debug(method + "authnRequest is null");
            }

            if (ssoResponse != null) {
                // Log dell'intera ssoResponse
                if (ssoResponse.toXMLString() != null) {
                    logger.info("| [transactionID= " + transactionID + "] | Response= "
                            + ssoResponse.toXMLString().replaceAll("(\\r|\\n)", ""));
                } else {

                    logger.debug(method + "Impossibile stampare la response");
                }

                if (ssoResponse.getInResponseTo() != null) {

                    logger.debug(method + "InResponseTo: " + ssoResponse.getInResponseTo());
                    log_value.put("InResponseTo", ssoResponse.getInResponseTo()); // String
                } else {

                    logger.debug(method + "InResponseTo: null ... ");
                }

                if (ssoResponse.getID() != null) {

                    logger.debug(method + "Resp_ID: " + ssoResponse.getID());
                    log_value.put("Resp_ID", ssoResponse.getID()); // String
                } else {

                    logger.debug(method + "Resp_ID: null ... ");
                }

                if (ssoResponse.getIssueInstant() != null) {

                    logger.debug(method + "Resp_IssueInstant: " + ssoResponse.getIssueInstant().toString());
                    log_value.put("Resp_IssueInstant", new Timestamp(ssoResponse.getIssueInstant().getTime())); // Date
                } else {

                    logger.debug(method + "Resp_IssueInstant: null ... ");
                }

                Status status = ssoResponse.getStatus();
                if (status != null && status.getStatusCode() != null) {
                    log_value.put("StatusCode", status.getStatusCode().getValue()); // String
                } else {

                    logger.debug(method + "StatusCode: null ... ");
                }
                if (status != null && status.getStatusMessage() != null) {
                    log_value.put("StatusMessage", status.getStatusMessage()); // String
                } else {

                    logger.debug(method + "StatusMessage: null ... ");
                }
            } else {

                logger.debug(method + "ssoResponse is null");
            }

            if (assertion != null) {

                // Recupero Codice Fiscale
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
                List<?> userVal = util.getAttributeVal(attributes, SPID_FISCALNUMBER_ATTRNAME);
                if (userVal != null && userVal.get(0) != null) {
                    log_value.put(SPID_FISCALNUMBER_ATTRNAME, userVal.get(0).toString()); // String
                } else {

                    logger.debug(method + SPID_FISCALNUMBER_ATTRNAME + ": null ... ");
                }
            } else {

                logger.debug(method + "assertion is null");
            }

            // Log dei valori pi importanti estrapolati singolarmente
            logger.info("[transactionID= " + transactionID + "] | Summary= " + log_value);

        } catch (SAML2Exception e) {
            logger.error(method + "SAML2Exception: ", e);
            e.printStackTrace();
            logger.error("SAML2Exception: " + e);
            return false;
        } catch (Exception e) {
            logger.error(method + "Exception: ", e);
            e.printStackTrace();
            logger.error("Exception: " + e);
            return false;
        }

        return true;
    }

    private boolean writeRecordSpid(Assertion assertion, AuthnRequest authnRequest,
            Response ssoResponse) {
        String method = "[writeRecordSpid]:: ";

        logger.debug(method + "inizio ... ");

        /*
         * TRACCIATURE SERVICE PROVIDER
         * - <AuthnRequest>;
         * - <Response>;
         * - AuthnReq_ID;
         * - AuthnReq_ IssueInstant;
         * - Resp_ID;
         * - Resp_ IssueInstant;
         * - Resp _ Issuer;
         * - Assertion_ID;
         * - Assertion_subject;
         * - Assertion_subject_NameQualifier;
         */
        Map<String, Object> col_val = new HashMap<String, Object>();

        try {
            if (authnRequest != null) {
                if (authnRequest.toXMLString() != null) {
                    // if(debug.messageEnabled())
                    // logger.debug(method + "AuthnRequest: " + authnRequest.toXMLString() );
                    col_val.put(CustomHandler.col_authn_request, (String) authnRequest.toXMLString()); // BLOB
                } else {

                    logger.debug(method + "AuthnRequest: null ... ");
                }

                if (authnRequest.getID() != null) {

                    logger.debug(method + "AuthnReq_ID: " + authnRequest.getID());
                    col_val.put(CustomHandler.col_authnreq_id, authnRequest.getID()); // String
                } else {

                    logger.debug(method + "AuthnReq_ID: null ... ");
                }

                if (authnRequest.getIssueInstant() != null) {

                    logger.debug(method + "AuthnReq_IssueInstant: " + authnRequest.getIssueInstant().toString());
                    col_val.put(CustomHandler.col_authnreq_issue_instant,
                            new Timestamp(authnRequest.getIssueInstant().getTime())); // Timestamp
                } else {

                    logger.debug(method + "AuthnReq_IssueInstant: null ... ");
                }
            }

            if (ssoResponse != null) {
                if (ssoResponse.toXMLString() != null) {
                    // if(debug.messageEnabled())
                    // logger.debug(method + "Response: " + ssoResponse.toXMLString() );
                    col_val.put(CustomHandler.col_response, ssoResponse.toXMLString()); // BLOB
                } else {

                    logger.debug(method + "Response: null ... ");
                }

                if (ssoResponse.getID() != null) {

                    logger.debug(method + "Resp_ID: " + ssoResponse.getID());
                    col_val.put(CustomHandler.col_resp_id, ssoResponse.getID()); // String
                } else {

                    logger.debug(method + "Resp_ID: null ... ");
                }

                if (ssoResponse.getIssueInstant() != null) {

                    logger.debug(method + "Resp_IssueInstant: " + ssoResponse.getIssueInstant().toString());
                    col_val.put(CustomHandler.col_resp_issue_instant,
                            new Timestamp(ssoResponse.getIssueInstant().getTime())); // Date
                } else {

                    logger.debug(method + "Resp_IssueInstant: null ... ");
                }

                if (ssoResponse.getIssuer() != null) {
                    logger.debug(method + "Resp_Issuer: " + ssoResponse.getIssuer().getValue());
                    logger.debug(method + "Resp_Issuer INT: " + ssoResponse.getIssuer().getValue().length());

                    col_val.put(CustomHandler.col_resp_issuer, ssoResponse.getIssuer().getValue()); // String
                } else {

                    logger.debug(method + "Resp_Issuer: null ... ");
                }
            }

            if (assertion != null) {
                if (assertion.getID() != null) {

                    logger.debug(method + "Assertion_ID: " + assertion.getID());
                    col_val.put(CustomHandler.col_assertion_id, assertion.getID()); // String
                } else {

                    logger.debug(method + "Assertion_ID: null ... ");
                }

                if (assertion.getSubject() != null) {

                    logger.debug(method + "Assertion_subject - getNameID().getValue: "
                            + assertion.getSubject().getNameID().getValue());

                    // col_val.put(SPIDHandler.col_assertion_subject, (String)
                    // assertion.getSubject().toXMLString() ); //BLOB
                    col_val.put(CustomHandler.col_assertion_subject,
                            (String) assertion.getSubject().getNameID().getValue()); // String
                } else {
                    logger.debug(method + "Assertion_subject: null ... ");
                }

                if (assertion.getSubject().getNameID() != null) {
                    logger.debug(method + "Assertion_subject_NameQualifier: "
                            + assertion.getSubject().getNameID().getNameQualifier());
                    logger.debug(method + "Assertion_subject_NameQualifier_ INT: "
                            + assertion.getSubject().getNameID().getNameQualifier().length());

                    col_val.put(CustomHandler.col_assertion_subject_namequalifier,
                            assertion.getSubject().getNameID().getNameQualifier()); // String
                } else {
                    logger.debug(method + "Assertion_subject_NameQualifier: null ... ");
                }

                // CODICE FISCALE
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
                List<?> userVal = util.getAttributeVal(attributes, SPID_FISCALNUMBER_ATTRNAME);
                if (userVal != null && userVal.get(0) != null) {
                    col_val.put(CustomHandler.col_fiscalcode, userVal.get(0).toString()); // String
                } else {

                    logger.debug(method + "Fiscalcode: null ... ");
                }

                /*
                 * STATUS CODE
                 * <saml2p:Status>
                 * <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
                 * <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>
                 * </saml2p:StatusCode>
                 * <saml2p:StatusMessage>ErrorCode nr22</saml2p:StatusMessage>
                 * </saml2p:Status>
                 */
                Status status = ssoResponse.getStatus();
                if (status != null && status.getStatusCode() != null) {
                    col_val.put(CustomHandler.col_statuscode, status.getStatusCode().getValue()); // String
                } else {

                    logger.debug(method + "Status Code: null ... ");
                }
                if (status != null && status.getStatusMessage() != null) {
                    col_val.put(CustomHandler.col_statuscode_message, status.getStatusMessage()); // String
                } else {

                    logger.debug(method + "Status Code Message: null ... ");
                }
            }
        } catch (SAML2Exception e) {
            logger.error(method + "SAML2Exception: ", e);
            e.printStackTrace();
        }

        // TODO

        CustomHandler db = null;

        try {
            db = new CustomHandler();
            db.connect();
            db.insertRow(col_val);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();

            logger.error(method, e);
            return false;
        } catch (SQLException e) {
            e.printStackTrace();

            logger.error(method, e);
            return false;
        } finally {
            if (db != null)
                try {
                    db.close();
                } catch (SQLException e) {
                    e.printStackTrace();

                    logger.error(method, e);
                    return false;
                }
        }
        return true;
    }

    private boolean redirectToFirstLogin(SSOToken ssoToken, String realm, HttpServletResponse response) {
        String method = "[redirectToFirstLogin]:: ";

        logger.debug(method + "inizio ... ");

        // se non deve essere effettuata la redirect esce dal metodo
        if (!redirectToFirstLogin)
            return false;

        String strLandingPage = "";
        if (FIRSTLOGIN_LANDINGPAGE == null || FIRSTLOGIN_LANDINGPAGE.trim().equals("")) {

            logger.error(method + "Error: " + FIRSTLOGIN_LANDINGPAGE + " undefined: exit");
            return false;
        } else {
            strLandingPage = FIRSTLOGIN_LANDINGPAGE;
        }

        try {
            /*
             * NON NECESSARIO
             * if( HEADER_IDSITO!=null ){
             * //imposta la variabile IDSITO
             * 
             * logger.debug( method + "______ REDIRECT_TO: " + REDIRECT_TO );
             * ssoToken.setProperty( "GOTO", REDIRECT_TO );
             * }
             */
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
            response.setHeader("Location", strLandingPage);

            logger.debug(method + "FirstLogin end, User[" + ssoToken.getPrincipal().getName() + "] redirect to: "
                    + strLandingPage);

            return true;
        } catch (Exception ex) {
            logger.error(method
                    + " Exception while setting session password property: "
                    + ex);
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private boolean isFirstLogin(SSOToken ssoToken, String realm) {
        String method = "[isFirstLogin]:: ";

        logger.debug(method + "inizio ... ");

        // se non deve essere effettuata la redirect esce dal metodo
        if (!redirectToFirstLogin)
            return false;

        String strUserIdRepoName = getAdvancedProperty(IDREPO);
        if (strUserIdRepoName == null || strUserIdRepoName.trim().equals("")) {
            if (CREATEUSER_IDREPO != null && !CREATEUSER_IDREPO.trim().equals("")) {
                strUserIdRepoName = CREATEUSER_IDREPO;
            }
        }

        String strAttributeName = "";

        if (FIRSTLOGIN_ATTRIBUTE == null || FIRSTLOGIN_ATTRIBUTE.trim().equals("")) {

            logger.debug(method + "FIRSTLOGIN_ATTRIBUTE undefined: exit");
            return primoAccesso;
        } else {
            strAttributeName = FIRSTLOGIN_ATTRIBUTE;
        }

        String strAttributeValue = "";

        if (FIRSTLOGIN_ATTRIBUTE_VAL == null || FIRSTLOGIN_ATTRIBUTE_VAL.trim().equals("")) {

            logger.debug(method + "FIRSTLOGIN_ATTRIBUTE_VAL undefined: exit");
            return primoAccesso;
        } else {
            strAttributeValue = FIRSTLOGIN_ATTRIBUTE_VAL;
        }

        logger.debug(method + IDREPO + "=" + strUserIdRepoName);

        try {
            if (ssoToken != null && ssoToken.getPrincipal().getName() != null) {
                String accountName = null;
                String[] accountNameArray = ssoToken.getPrincipal().getName().split(",");
                if (accountNameArray != null) {
                    int i = accountNameArray[0].indexOf("=");
                    accountName = accountNameArray[0].substring(i + 1);
                }

                if (accountName != null && !accountName.isEmpty()) {

                    logger.debug(method + " accountName: " + accountName);

                    Map<String, Set<String>> attributeValueMap = null;
                    if (strUserIdRepoName != null && !strUserIdRepoName.isEmpty()) {
                        attributeValueMap = repoUtil.getCUSTOMUserAttribute(accountName, realm, strUserIdRepoName, null,
                                userContainer, strAttributeName);
                        if (attributeValueMap != null) {
                            logger.debug(method + " attributeValueMap: " + attributeValueMap.size());
                        } else {
                            @SuppressWarnings("unused")
                            List<AMIdentity> users = repoUtil.getUserStoreIdentity(accountName, realm);
                        }
                    } else {
                        List<AMIdentity> users = repoUtil.getUserStoreIdentity(accountName, realm);
                        if (users != null && !users.isEmpty()) // utente esistente
                        {
                            if (users.size() > 1) { // TODO
                                logger.debug(method + "trovate piu occorrenze sullo UserStore per name[" + accountName
                                        + "] e realm[" + realm + "]");
                            } else {
                                AMIdentity usr = users.get(0);

                                if (usr != null) {
                                    attributeValueMap = usr.getAttributes();
                                }
                            }
                        } else
                            logger.error(method + " utente non trovato");
                    }

                    logger.debug(method + strAttributeName + "=" + strAttributeValue);

                    for (Entry<String, Set<String>> entry : attributeValueMap.entrySet()) {
                        String attributeName = entry.getKey();
                        Set<String> attributeValue = entry.getValue();

                        logger.debug(method + " attributeName[" + attributeName + "][" + attributeValue + "]");
                        if (attributeName != null && attributeName.equalsIgnoreCase(strAttributeName)
                                && attributeValue != null && attributeValue.contains(strAttributeValue)) {
                            logger.debug(method + " attributeName: " + attributeName);
                            logger.debug(method + " strAttributeName: " + strAttributeName);
                            logger.debug(method + " attributeValue: " + attributeValue);
                            logger.debug(method + " strAttributeValue: " + strAttributeValue);
                            primoAccesso = true;
                        }
                    }
                }
            }
        } catch (SSOException sse) {
            logger.error(method + " SSOException while setting session password property: " + sse);
        } catch (Exception ex) {
            logger.error(method
                    + " Exception while setting session password property: "
                    + ex);
        }

        logger.debug(method + " primoAccesso: " + primoAccesso);
        return primoAccesso;
    }

    /**
     * Status code for Single Sign-on success.
     */
    public static final int SUCCESS = 0;

    /**
     * Status code for invalid response from <code>IDP</code>.
     */
    public static final int INVALID_RESPONSE = 1;

    /**
     * Status code for federation failure due to unable to write account
     * federation info.
     */
    public static final int FEDERATION_FAILED_WRITING_ACCOUNT_INFO = 3;

    /**
     * Status code for Single Sign-On failure due to internal session error.
     */
    public static final int SSO_FAILED_SESSION_ERROR = 4;

    /**
     * Status code for Single Sign-On failure due attribute mapping error.
     */
    public static final int SSO_FAILED_ATTRIBUTE_MAPPING = 5;

    /**
     * Status code for Single Sign-On failure due to no user mapping.
     */
    public static final int SSO_FAILED_NO_USER_MAPPING = 6;

    /**
     * Status code for Single Sign-On failure due to inactive user account.
     */
    public static final int SSO_FAILED_AUTH_USER_INACTIVE = 7;

    /**
     * Status code for Single Sign-On failure due to locked user account.
     */
    public static final int SSO_FAILED_AUTH_USER_LOCKED = 8;

    /**
     * Status code for Single Sign-On failure due to expired user account.
     */
    public static final int SSO_FAILED_AUTH_ACCOUNT_EXPIRED = 9;

    /**
     * Status code for Single Sign-On failure due to unable to generate
     * user session.
     */
    public static final int SSO_FAILED_SESSION_GENERATION = 10;

    /**
     * Status code for Single Sign-On failure due to unable to retrieve
     * meta data.
     */
    public static final int SSO_FAILED_META_DATA_ERROR = 11;

    /**
     * Constants for hosted entity id parameter
     */
    public static final String HOSTED_ENTITY_ID = "HOSTED_ENTITY_ID";

    /**
     * Constants for the realm of the hosted entity parameter.
     */
    public static final String REALM = "REALM";

}
