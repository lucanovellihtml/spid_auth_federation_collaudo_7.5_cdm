package com.sun.identity.custom.util;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Classe introdotta per la gestione delle utenze eidas aziende sull'IDM;
 * E' stato cambiato il valore della variabile DBGNAME per creare un nuovo file di audit;
 * La logica  è uguale alla logica per gestire le utenze cittadino, è stata cambiata la variabile "GET_URL/PATCH_URL" con i puntamenti all'entity company;
 * E' stata modificata la mappatura dei campi tra ldap-idm;
 */
public class CustomEidasAziendeRestUtil {

    private static com.sun.identity.shared.debug.Debug debug = null;
    private static String sGlobalUrlService;

    //MODIFICA LOG EIDAS AZIENDE
    private static final String GET_URL = "/managed/company?_queryFilter=/userName+eq+\'";
    private static final String PATCH_URL = "/managed/company/";

    private static String sGlobalAdminUser = null;
    private static String sGlobalAdminPwd = null;

    private static HashMap<String, String> mapAttrLdapIdm = new HashMap<String, String>();

    /**
     * @param sBaseUrlService URL del server IDM sul quale effettuare le chiamate REST ex: https://openidm.test.comune/openidm
     * @param sAdminUser      userName dell'utente amministrativo con il quale effettuare la
     *                        chiamata REST
     * @param sAdminPwd       password dell'utente amministrativo con il quale effettuare la
     *                        chiamata REST
     */
    public CustomEidasAziendeRestUtil(String sBaseUrlService, String sAdminUser, String sAdminPwd) throws Exception {
        String method = "[CustomAziendeRestUtil]:: ";
        if (debug == null) {
            debug = com.sun.identity.shared.debug.Debug.getInstance("CustomEidasAziendeRestUtil");
        }

        if (sBaseUrlService != null && !sBaseUrlService.isEmpty() &&
                sAdminUser != null && !sAdminUser.isEmpty() &&
                sAdminPwd != null && !sAdminPwd.isEmpty()) {
            sGlobalUrlService = sBaseUrlService;
            sGlobalAdminUser = sAdminUser;
            sGlobalAdminPwd = sAdminPwd;
        } else {
            debug.error(method + "Rest Base URL Service OR Admin User OR Admin Password are empty or null");
            Exception se = new Exception("Eccezione Rest Base URL Service OR Admin User OR Admin Password are empty or null");
            throw se;
        }

        //In caso di aggiunta di un attributo LDAP da mofificare ricordarsi di aggiungere il mapping IDM
        //Costruisce il Map per la definizione degli attributi ( LDAP , IDM )
        mapAttrLdapIdm.put("uid", "userName"); //sistemato
        mapAttrLdapIdm.put("inetUserStatus", "accountStatus");
        mapAttrLdapIdm.put("cdmTipoUtente", "cdmTipoUtente"); //aggiunto
        mapAttrLdapIdm.put("employeeType", "employeeType"); //aggiunto

        //MODIFICA LOG EIDAS AZIENDE
        mapAttrLdapIdm.put("o", "CompanyName"); //aggiunto per spid aziende //sistemato
        mapAttrLdapIdm.put("cdmRegisteredOffice", "cdmRegisteredOffice"); // aggiunto per eidas aziende
        mapAttrLdapIdm.put("cdmSedeProvincia", "cdmSedeProvincia"); // aggiunto per eidas aziende
        mapAttrLdapIdm.put("cdmSedeCap", "cdmSedeCap"); // aggiunto per eidas aziende
        mapAttrLdapIdm.put("cdmSedeVia", "cdmSedeVia"); // aggiunto per eidas aziende
        mapAttrLdapIdm.put("cdmSedeComune", "cdmSedeComune"); // aggiunto per eidas aziende
        mapAttrLdapIdm.put("cdmPartitaIva", "cdmPartitaIva"); // aggiunto per eidas aziende

//      mapAttrLdapIdm.put("cdmNascitaCodiceComune", "cdmPlaceOfBirthDelegato"); //sistemato
//      mapAttrLdapIdm.put("sn", "sn"); //sistemato
//      mapAttrLdapIdm.put("cdmNascitaData", "cdmDateOfBirthDelegato"); //sistemato
//      mapAttrLdapIdm.put("cdmSesso", "cdmGenderDelegato"); //sistemato
//      mapAttrLdapIdm.put("givenname", "givenName"); //sistemato
//      mapAttrLdapIdm.put("postalCode", "postalCode"); //sistemato
//      mapAttrLdapIdm.put("st", "ResidenceProvince"); //sistemato
//      mapAttrLdapIdm.put("street", "ResidenceAddress"); //sistemato
//      mapAttrLdapIdm.put("cn", "description");  //aggiunto
//      mapAttrLdapIdm.put("cdmDomicilioDigitale", "PecEmail"); //sistemato
//      mapAttrLdapIdm.put("cdmResidenzaCodiceNazione", "countryCode"); // aggiunto per spid aziende //sistemato
//      mapAttrLdapIdm.put("l", "ResidenceMunicipality"); // aggiunto per spid aziende //sistemato
//		mapAttrLdapIdm.put("userPassword", "password");
//		mapAttrLdapIdm.put("telephoneNumber", "telephoneNumber");
//		mapAttrLdapIdm.put("mail", "mail");
//		mapAttrLdapIdm.put("cdmPartitaIva", "x");
//		mapAttrLdapIdm.put("address", "x");
//		mapAttrLdapIdm.put("idCard", "x");
//		mapAttrLdapIdm.put("companyName", "x");
//		mapAttrLdapIdm.put("digitalAddress", "x");
    }

    private static String getUserAttrMappingIDM(String sAttLDAP) {
        String method = "[updateIDMUser]:: ";

        if (sAttLDAP != null && !sAttLDAP.isEmpty() && mapAttrLdapIdm != null && !mapAttrLdapIdm.isEmpty()) {
            if (debug.messageEnabled())
                debug.message(method + "Attributo LDAP[" + sAttLDAP + "] Attributo IDM[" + mapAttrLdapIdm.get(sAttLDAP) + "]");
            return mapAttrLdapIdm.get(sAttLDAP);
        } else return null;
    }

    /**
     * @param sUid  userName dell'utente IDM da aggiornare
     * @param attrs
     * @return
     * @throws IOException
     */
    public boolean updateIDMUser(String sUid, Map<String, Set<String>> attrs) throws IOException {
        String method = "[updateIDMUser]:: ";

        if (attrs == null || attrs.isEmpty()) {
            debug.error(method + " Specificare gli attributi dello user IDM da aggiornare");
            return false;
        }
        if (sUid == null || sUid.isEmpty()) {
            debug.error(method + " Specificare lo userName dello user IDM da aggiornare");
            return false;
        }

        try {
            debug.message(method + "INIZIO GET User REST IDM [" + sUid + "]");
            /* GET */
            JSONObject userJsonObject = sendGET(sUid);
            if (userJsonObject != null && userJsonObject.getString("_id") != null) {
                if (debug.messageEnabled())
                    debug.message(method + "GET userJsonObject:: " + userJsonObject.toString());
                String id = userJsonObject.getString("_id");
                if (debug.messageEnabled()) {
                    debug.message(method + "GET userJsonObject GET _ID :: " + id);
                    debug.message(method + "___GET DONE");
                }

                /* PATCH */
                debug.message(method + "INIZIO Update User REST IDM userName [" + sUid + "] ed id IDM[" + id + "]");
                int result = sendPATCH(id, attrs);
                //[ 200 : OK , 1 : ERRORE GENERICO , 2 : parametri non validi o null ]
                if (result == 200)
                    return true;
                else {
                    debug.error(method + "ERRORE PATCH REST IDM userName [" + sUid + "] return Code [" + result + "]");
                }
            } else {
                debug.error(method + "errore Get User [" + sUid + "]  utente inesistente");
            }
        } catch (JSONException e) {
            debug.error(method + e.getMessage());
        }
        return false;
    }

    /*
     * How to ignore SSL certificate errors
     */
    private static CloseableHttpClient noSslHttpClient()
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        final SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, (x509CertChain, authType) -> true)
                .build();
        return HttpClientBuilder.create().setSSLContext(sslContext)
                .setConnectionManager(new PoolingHttpClientConnectionManager(RegistryBuilder
                        .<ConnectionSocketFactory>create().register("http", PlainConnectionSocketFactory.INSTANCE)
                        .register("https", new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE))
                        .build()))
                .build();
    }

    /**
     * -- UTENTE con query per nome curl --header "X-OpenIDM-Username:
     * openidm-admin" --header "X-OpenIDM-Password: openidm-admin" --request GET
     * "https://openidm.test.comune/openidm/managed/company?_queryFilter=/userName+eq+'dpace'&_prettyPrint=true"
     * --insecure
     *
     * @throws IOException
     */
    private static JSONObject sendGET(String sUserName) throws IOException {
        String method = "[sendGET]:: ";

        CloseableHttpClient httpClient = HttpClients.createDefault();
        BufferedReader reader = null;
        JSONObject userJsonObject = null;
        String sURL = null;

        try {

            sURL = sGlobalUrlService + GET_URL + sUserName + "\'&_prettyPrint=true";

            //MODIFICA LOG EIDAS AZIENDE
            //httpClient = noSslHttpClient();

            HttpGet httpGet = new HttpGet(sURL);
            httpGet.addHeader("X-OpenIDM-Username", sGlobalAdminUser);
            httpGet.addHeader("X-OpenIDM-Password", sGlobalAdminPwd);
            httpGet.addHeader("Content-Type", "application/json");

            CloseableHttpResponse httpResponse = httpClient.execute(httpGet);

            if (httpResponse != null && httpResponse.getStatusLine() != null && httpResponse.getStatusLine().getStatusCode() == 200) {
                reader = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

                String inputLine;
                StringBuffer response = new StringBuffer();

                while ((inputLine = reader.readLine()) != null) {
                    response.append(inputLine);
                }

                // converte la response in JSON
                JSONObject responseJsonObject = new JSONObject(response.toString());

                JSONArray result = responseJsonObject.getJSONArray("result");
                for (int i = 0; i < result.length(); i++) {
                    userJsonObject = new JSONObject(result.get(i).toString());
                }
            } else {
                debug.error(method + "GET Response Status ERROR :: " + httpResponse.getStatusLine().getStatusCode());
            }
        } catch (JSONException e) {
            debug.error(method + e.getMessage());
        } finally {
            reader.close();
            httpClient.close();
        }
        return userJsonObject;
    }

    /**
     * curl.exe --header "X-OpenIDM-Username: openidm-admin" --header
     * "X-OpenIDM-Password: password" --header "Content-Type:
     * application/json" --request PATCH --data "[ { \"operation\" :
     * \"replace\", \"field\" : \"givenName\", \"value\" : \"Agnese\" } ]"
     * "https://openidm.test.comune/openidm/managed/company/d39ca46f-f154-444b-9b62-27a27a5dcf91"
     * --insecure
     *
     * @throws IOException
     */

    /**
     * @param uid   _id dell'utente IDM da aggiornare
     * @param attrs Attributi da aggiornare
     * @return Ritorna un int con lo Status Code dell httpResponse [ 200 : OK ,
     * 1 : ERRORE GENERICO , 2 : parametri non validi o null ]
     * @throws IOException
     */
    private static int sendPATCH(String uid, Map<String, Set<String>> attrs)
            throws IOException {
        String method = "[sendPATCH]:: ";

        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpResponse httpResponse = null;
        BufferedReader reader = null;
        int returnCode = 1;

        if (uid == null || uid.isEmpty() || sGlobalAdminUser == null || sGlobalAdminUser.isEmpty() || sGlobalAdminPwd == null
                || sGlobalAdminPwd.isEmpty() || attrs == null || attrs.isEmpty())
            return 2;

        try {
            //MODIFICA LOG EIDAS AZIENDE
            //httpClient = noSslHttpClient();

            String sURL = sGlobalUrlService + PATCH_URL + uid;

            debug.error(method + "PATCH sURL :: " + sURL);

            HttpPatch httpPatch = new HttpPatch(sURL);
            httpPatch.addHeader("X-OpenIDM-Username", sGlobalAdminUser);
            httpPatch.addHeader("X-OpenIDM-Password", sGlobalAdminPwd);
            httpPatch.addHeader("Content-Type", "application/json");


            // imposta il JSON per il PATCH
            JSONObject jsonPostObject = null;
            JSONArray jsonPostArray = new JSONArray();

            for (Entry<String, Set<String>> entry : attrs.entrySet()) {
                jsonPostObject = new JSONObject();
                jsonPostObject.put("operation", "replace");
                //prende il valore corrispondete dal MAP tra LDAP e IDM
                if (entry.getKey() != null) {
                    String sIDMAttr = getUserAttrMappingIDM(entry.getKey());
                    if (sIDMAttr != null) {
                        jsonPostObject.put("field", sIDMAttr);
                        if (entry.getValue() != null) {
                            Object[] userVals = entry.getValue().toArray();
                            String sVals = userVals[0].toString();
                            //imposta formato corretto (AAAAMMGGHHMMSS) per l'attributo Data di nasciata cdmNascitaData
                            if (sIDMAttr.equalsIgnoreCase("BirthDate")) {
                                jsonPostObject.put("value", sVals);
                            } else {
                                jsonPostObject.put("value", sVals);
                            }
                        } else {
                            // imposta null
                            jsonPostObject.put("value", new HashSet<String>());
                        }
                        jsonPostArray.put(jsonPostObject);
                    } else {
                        debug.message(method + "Mapping LDAP-IDM non trovato per attributo LDAP [" + entry.getKey() + "]");
                    }
                }
            }

            //MODIFICA LOG EIDAS AZIENDE
            StringEntity jsonEntity = new StringEntity(jsonPostArray.toString());

            httpPatch.setEntity(jsonEntity);

            httpResponse = httpClient.execute(httpPatch);
            returnCode = httpResponse.getStatusLine().getStatusCode();
            if (returnCode == 200) {
                reader = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

                String inputLine;
                StringBuffer sResponse = new StringBuffer();

                while ((inputLine = reader.readLine()) != null) {
                    sResponse.append(inputLine);
                }

                debug.message(method + "PATCH User[" + uid + "] Avvenuta con successo! ");

                if (debug.messageEnabled())
                    debug.message(method + "________________PATCH response :: " + sResponse);
            } else {

                //MODIFICA LOG SPID AZIENDE
                reader = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

                String inputLine;
                StringBuffer sResponse = new StringBuffer();

                while ((inputLine = reader.readLine()) != null) {
                    sResponse.append(inputLine);
                }

                debug.error("PATCH User[" + uid + "] Response Status ERROR :: " + httpResponse.getStatusLine().getStatusCode());
            }

        } catch (JSONException e) {
            debug.error(method + e.getMessage());
        } finally {
            if (httpResponse != null)
                httpResponse.close();
            if (reader != null)
                reader.close();
            if (httpClient != null)
                httpClient.close();
        }

        return returnCode;
    }
}
