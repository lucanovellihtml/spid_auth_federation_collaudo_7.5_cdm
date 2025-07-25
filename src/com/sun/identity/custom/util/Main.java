package com.sun.identity.custom.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Main {

    public static void main(String[] args)
            throws JSONException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        try {
            sendGETComuni(true);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendGETComuni(Boolean flagInput)
            throws IOException, JSONException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        String method = "[sendGET]:: ";

        CloseableHttpClient httpClient = HttpClients.createDefault();
        BufferedReader reader = null;
        JSONObject userJsonObject = null;
        String sURL = null;

        try {

            // sURL = sGlobalUrlService + GET_URL + sUserName + "\'&_prettyPrint=true";
            // sURL =
            // "https://openidm7.test.comune/openidm/managed/Comuni?_queryFilter=nome+eq+'Roma'";
            sURL = "https://openidm7.test.comune/openidm/managed/Comuni?_queryFilter=true";

            // MODIFICA LOG SPID AZIENDE
            httpClient = noSslHttpClient();

            HttpGet httpGet = new HttpGet(sURL);
            httpGet.addHeader("X-OpenIDM-Username", "ciamgestione");
            httpGet.addHeader("X-OpenIDM-Password", "cVF!td$He6fgRPMr");
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
                    String comune = "NaPoLi";

                    JSONArray result = responseJsonObject.getJSONArray("result");
                    for (int i = 0; i < result.length(); i++) {
                        userJsonObject = new JSONObject(result.get(i).toString());
                        if (userJsonObject.getString("nome").toLowerCase().equals(comune.toLowerCase()))
                            System.out.println("CODICE COMUNE: " + userJsonObject.getString("codice"));
                    }
                } else {
                    // Casistica se abbiamo il codice e dobbiamo trovate il nome del comune
                    String codice = "F839";

                    JSONArray result = responseJsonObject.getJSONArray("result");
                    for (int i = 0; i < result.length(); i++) {
                        userJsonObject = new JSONObject(result.get(i).toString());
                        if (userJsonObject.getString("codice").equals(codice))
                            System.out.println("NOME COMUNE: " + userJsonObject.getString("nome"));
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

}
