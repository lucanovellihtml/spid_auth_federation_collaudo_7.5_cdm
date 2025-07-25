package com.sun.identity.custom.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.net.ssl.SSLContext;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomRestUtil {

	private static Logger logger = null;
	private static String sGlobalUrlService;
	private static final String GET_URL = "/managed/user?_queryFilter=/userName+eq+\'";
	private static final String PATCH_URL = "/managed/user/";

	private static String sGlobalAdminUser = null;
	private static String sGlobalAdminPwd = null;

	private static HashMap<String, String> mapAttrLdapIdm = new HashMap<String, String>();

	/**
	 *
	 * @param sBaseUrlService
	 *                        URL del server IDM sul quale effettuare le chiamate
	 *                        REST ex: https://openidm.test.comune/openidm
	 * @param sAdminUser
	 *                        userName dell'utente amministrativo con il quale
	 *                        effettuare la
	 *                        chiamata REST
	 * @param sAdminPwd
	 *                        password dell'utente amministrativo con il quale
	 *                        effettuare la
	 *                        chiamata REST
	 */
	public CustomRestUtil(String sBaseUrlService, String sAdminUser, String sAdminPwd) throws Exception {
		String method = "[CustomRestUtil]:: ";

		if (logger == null) {
			logger = LoggerFactory.getLogger(CustomRestUtil.class);
		}

		if (sBaseUrlService != null && !sBaseUrlService.isEmpty() &&
				sAdminUser != null && !sAdminUser.isEmpty() &&
				sAdminPwd != null && !sAdminPwd.isEmpty()) {
			sGlobalUrlService = sBaseUrlService;
			sGlobalAdminUser = sAdminUser;
			sGlobalAdminPwd = sAdminPwd;
		} else {
			logger.error(method + "Rest Base URL Service OR Admin User OR Admin Password are empty or null");
			Exception se = new Exception(
					"Eccezione Rest Base URL Service OR Admin User OR Admin Password are empty or null");
			throw se;
		}

		// In caso di aggiunta di un attributo LDAP da mofificare ricordarsi di
		// aggiungere il mapping IDM
		// Costruisce il Map per la definizione degli attributi ( LDAP , IDM )
		mapAttrLdapIdm.put("uid", "userName");
		mapAttrLdapIdm.put("inetUserStatus", "accountStatus");
		mapAttrLdapIdm.put("sn", "sn");
		mapAttrLdapIdm.put("cdmNascitaData", "BirthDate");
		mapAttrLdapIdm.put("cdmSesso", "gender");
		mapAttrLdapIdm.put("givenname", "givenName");
		mapAttrLdapIdm.put("cdmCodiceFiscale", "cdmCodiceFiscale");
		mapAttrLdapIdm.put("postalCode", "postalCode");
		mapAttrLdapIdm.put("st", "ResidenceProvince");
		mapAttrLdapIdm.put("cdmNascitaCodiceComune", "cdmNascitaCodiceComune");
		mapAttrLdapIdm.put("street", "ResidenceAddress");
		mapAttrLdapIdm.put("SPIDemail", "SPIDemail");
		mapAttrLdapIdm.put("Spidmobile", "SPIDMobile");
		mapAttrLdapIdm.put("cn", "description"); // aggiunto
		mapAttrLdapIdm.put("cdmTipoUtente", "cdmTipoUtente"); // aggiunto
		mapAttrLdapIdm.put("employeeType", "employeeType"); // aggiunto

		/*
		 * Modifica gestione toponomastica.
		 * Aggiunto il campo cdmVia e cdmNumeroCivico
		 */
		mapAttrLdapIdm.put("cdmVia", "cdmVia");
		mapAttrLdapIdm.put("cdmNumeroCivico", "cdmNumeroCivico");

		// MODIFICA LOG SPID AZIENDE
		mapAttrLdapIdm.put("cdmDomicilioDigitale", "PecEmail"); // aggiunto

		// mapAttrLdapIdm.put("userPassword", "password");
		// mapAttrLdapIdm.put("telephoneNumber", "telephoneNumber");
		// mapAttrLdapIdm.put("mail", "mail");
		// mapAttrLdapIdm.put("cdmPartitaIva", "x");
		// mapAttrLdapIdm.put("address", "x");
		// mapAttrLdapIdm.put("idCard", "x");
		// mapAttrLdapIdm.put("companyName", "x");
		// mapAttrLdapIdm.put("digitalAddress", "x");
		// mapAttrLdapIdm.put("registeredOffice", "x");
	}

	private static String getUserAttrMappingIDM(String sAttLDAP) {
		String method = "[updateIDMUser]:: ";

		if (sAttLDAP != null && !sAttLDAP.isEmpty() && mapAttrLdapIdm != null && !mapAttrLdapIdm.isEmpty()) {

			logger.debug(method + "Attributo LDAP[" + sAttLDAP + "] Attributo IDM[" + mapAttrLdapIdm.get(sAttLDAP)
					+ "]");
			return mapAttrLdapIdm.get(sAttLDAP);
		} else
			return null;
	}

	/**
	 *
	 * @param sUid  userName dell'utente IDM da aggiornare
	 * @param attrs
	 * @return
	 * @throws IOException
	 */
	public boolean updateIDMUser(String sUid, Map<String, Set<String>> attrs) throws IOException {
		String method = "[updateIDMUser]:: ";

		if (attrs == null || attrs.isEmpty()) {
			logger.error(method + " Specificare gli attributi dello user IDM da aggiornare");
			return false;
		}
		if (sUid == null || sUid.isEmpty()) {
			logger.error(method + " Specificare lo userName dello user IDM da aggiornare");
			return false;
		}

		try {
			logger.debug(method + "INIZIO GET User REST IDM [" + sUid + "]");
			/* GET */
			JSONObject userJsonObject = sendGET(sUid);
			if (userJsonObject != null && userJsonObject.getString("_id") != null) {

				logger.debug(method + "GET userJsonObject:: " + userJsonObject.toString());
				String id = userJsonObject.getString("_id");

				logger.debug(method + "GET userJsonObject GET _ID :: " + id);
				logger.debug(method + "___GET DONE");

				/* PATCH */
				logger.debug(method + "INIZIO Update User REST IDM userName [" + sUid + "] ed id IDM[" + id + "]");
				int result = sendPATCH(id, attrs);
				// [ 200 : OK , 1 : ERRORE GENERICO , 2 : parametri non validi o null ]
				if (result == 200)
					return true;
				else {
					logger.error(method + "ERRORE PATCH REST IDM userName [" + sUid + "] return Code [" + result + "]");
				}
			} else {
				logger.error(method + "errore Get User [" + sUid + "]  utente inesistente");
			}
		} catch (JSONException e) {
			logger.error(method + e.getMessage());
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
	 * "https://openidm.test.comune/openidm/managed/user?_queryFilter=/userName+eq+'dpace'&_prettyPrint=true"
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

			// MODIFICA LOG SPID AZIENDE
			// httpClient = noSslHttpClient();

			HttpGet httpGet = new HttpGet(sURL);
			httpGet.addHeader("X-OpenIDM-Username", sGlobalAdminUser);
			httpGet.addHeader("X-OpenIDM-Password", sGlobalAdminPwd);
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

				JSONArray result = responseJsonObject.getJSONArray("result");
				for (int i = 0; i < result.length(); i++) {
					userJsonObject = new JSONObject(result.get(i).toString());
				}
			} else {
				logger.error(method + "GET Response Status ERROR :: " + httpResponse.getStatusLine().getStatusCode());
			}
		} catch (JSONException e) {
			logger.error(method + e.getMessage());
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
	 * "https://openidm.test.comune/openidm/managed/user/d39ca46f-f154-444b-9b62-27a27a5dcf91"
	 * --insecure
	 *
	 * @throws IOException
	 */

	/**
	 *
	 * @param uid
	 *              _id dell'utente IDM da aggiornare
	 * @param attrs
	 *              Attributi da aggiornare
	 * @return Ritorna un int con lo Status Code dell httpResponse [ 200 : OK ,
	 *         1 : ERRORE GENERICO , 2 : parametri non validi o null ]
	 * @throws IOException
	 */
	private static int sendPATCH(String uid, Map<String, Set<String>> attrs)
			throws IOException {
		String method = "[sendPATCH]:: ";

		CloseableHttpClient httpClient = HttpClients.createDefault();
		CloseableHttpResponse httpResponse = null;
		BufferedReader reader = null;
		int returnCode = 1;

		if (uid == null || uid.isEmpty() || sGlobalAdminUser == null || sGlobalAdminUser.isEmpty()
				|| sGlobalAdminPwd == null
				|| sGlobalAdminPwd.isEmpty() || attrs == null || attrs.isEmpty())
			return 2;

		try {
			// MODIFICA LOG SPID AZIENDE
			// httpClient = noSslHttpClient();

			String sURL = sGlobalUrlService + PATCH_URL + uid;

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
				// prende il valore corrispondete dal MAP tra LDAP e IDM
				if (entry.getKey() != null) {
					String sIDMAttr = getUserAttrMappingIDM(entry.getKey());
					if (sIDMAttr != null) {
						jsonPostObject.put("field", sIDMAttr);
						if (entry.getValue() != null) {
							Object[] userVals = entry.getValue().toArray();
							String sVals = userVals[0].toString();
							// imposta formato corretto (AAAAMMGGHHMMSS) per l'attributo Data di nasciata
							// cdmNascitaData
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
						logger.debug(
								method + "Mapping LDAP-IDM non trovato per attributo LDAP [" + entry.getKey() + "]");
					}
				}
			}

			// String stringToParse = "[ { \"operation\" : \"replace\",
			// \"field\" : \"givenName\", \"value\" : \"Domenico\", \"field\" :
			// \"sn\", \"value\" : \"Paoli\" } ]";
			// StringEntity jsonEntity = new StringEntity(stringToParse);

			logger.debug(method + "_______________PATCH jsonPostArray :: " + jsonPostArray.toString());
			StringEntity jsonEntity = new StringEntity(jsonPostArray.toString());

			logger.debug(method + "PATCH jsonEntity :: " + jsonEntity);

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

				logger.debug(method + "PATCH User[" + uid + "] Avvenuta con successo! ");

				logger.debug(method + "________________PATCH response :: " + sResponse);
			} else {
				logger.error("PATCH User[" + uid + "] Response Status ERROR :: "
						+ httpResponse.getStatusLine().getStatusCode());
			}

		} catch (JSONException e) {
			logger.error(method + e.getMessage());
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
	public void sendGETComuni(Boolean flagInput, String input,
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
			sURL = sGlobalUrlService;

			httpClient = noSslHttpClient();

			HttpGet httpGet = new HttpGet(sURL);
			httpGet.addHeader("X-OpenIDM-Username", sGlobalAdminUser);
			httpGet.addHeader("X-OpenIDM-Password", sGlobalAdminPwd);
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

					logger.debug(method
							+ " Siamo nella casistica dove abbiamo il nome del comune e dobbiamo trovare il codice");

					String comune = input;

					JSONArray result = responseJsonObject.getJSONArray("result");
					for (int i = 0; i < result.length(); i++) {
						userJsonObject = new JSONObject(result.get(i).toString());
						if (userJsonObject.getString("nome").toLowerCase().equals(comune.toLowerCase())) {

							logger.debug(method
									+ "[cdmResidenzaCodiceComune] = " + "[" + userJsonObject.getString("codice")
									+ "]");

							userAttrMap.put("cdmResidenzaCodiceComune",
									Arrays.asList(userJsonObject.getString("codice")));

						}
					}
				} else {

					logger.debug(method
							+ " Siamo nella casistica dove abbiamo il codice del comune e dobbiamo trovare il nome");

					// Casistica se abbiamo il codice e dobbiamo trovate il nome del comune
					String codice = input;
					JSONArray result = responseJsonObject.getJSONArray("result");

					for (int i = 0; i < result.length(); i++) {

						userJsonObject = new JSONObject(result.get(i).toString());

						if (userJsonObject.getString("codice").equals(codice)) {

							logger.debug(method
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

	/*
	 * How to execute HTTP requests via Proxy
	 */
	// HttpResponse requestViaProxy(String sProxyHost, String sProxyPort) throws
	// ClientProtocolException, IOException {
	// return Request.Get(CustomRestUtil.sGlobalUrlService)
	// .addHeader("app-header", "example")
	// .viaProxy(new HttpHost("myproxy", 8080))
	// .execute().returnResponse();
	// }
	// public static String ignoreSslErrorsRequest() throws Exception {
	// Executor executor = Executor.newInstance(noSslHttpClient());
	// return
	// executor.execute(Request.Get(CustomRestUtil.sGlobalUrlService)).returnContent().asString();
	// }
	//

}
