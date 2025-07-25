package com.sun.identity.custom.util;

import java.util.*;
import java.util.Map.Entry;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.idm.IdRepoAuditorFactory;
import org.forgerock.openam.idrepo.ldap.DJLDAPv3RepoFactory;

import com.google.inject.Injector;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.common.DNUtils;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.idm.IdRepo;
import org.forgerock.am.identity.presentation.IdRepoBundle;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdRepoListener;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchOpModifier;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomRepoUtil {
    private static String CLASSNAME = "CustomRepoUtil";
    static SSOToken adminToken;
    private static Logger logger = null;
    private static String GROUP_USERATTR = "memberOf";
    private static String GROUP_ATTR = "uniqueMember";

    // TODO da verificare ...
    private static final String AMSDK_PLUGIN = "com.iplanet.am.sdk.AMSDKRepo";

    // DATA STORE CONFIGURATION NAME
    final private static String DS_SEARCH_BASE_CONF_NAME = "sun-idrepo-ldapv3-config-psearchbase";
    final private static String DS_PEOPLE_CONTAINER_NAME_CONF_NAME = "sun-idrepo-ldapv3-config-people-container-name";
    final private static String DS_PEOPLE_CONTAINER_VALUE_CONF_NAME = "sun-idrepo-ldapv3-config-people-container-value";
    final private static String DS_ORGANIZATION_NAME_CONF_NAME = "sun-idrepo-ldapv3-config-organization_name";

    static ServiceConfigManager idRepoServiceConfigManager;

    public CustomRepoUtil() {
        if (logger == null) {
            logger = LoggerFactory.getLogger(CustomRepoUtil.class);
        }
        try {
            adminToken = AdminTokenAction.getInstance().run();
            idRepoServiceConfigManager = new ServiceConfigManager(adminToken, IdConstants.REPO_SERVICE, "1.0");
        } catch (SSOException ssoex) {
            logger.error(CLASSNAME + ".static:", ssoex);
        } catch (SMSException smsex) {
            logger.error(CLASSNAME + ".static:", smsex);
        }
    }

    /**
     * Metodo che fa una ricerca sullo userstore delle identità con il nome passatto
     * come parametro.
     * 
     * @param name  Id dell'utente da cercare
     * @param realm Realm in cui cercare l'utente
     * @return List<AMIdentity> Lista di identità utente trovate
     */
    public List<AMIdentity> getUserStoreIdentity(String name, String realm) {
        String method = "[getUserStoreIdentity]:: ";

        logger.debug(method + " --------- ricerca utente [" + name + "] e realm[" + realm + "] ------------ ");

        List<AMIdentity> users = new ArrayList<AMIdentity>();

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();
        AMIdentityRepository idRepo;
        try {
            idRepo = new AMIdentityRepository(realm, adminToken);

            if (idRepo != null) {
                IdSearchControl ctrl = new IdSearchControl();
                IdSearchResults ident = idRepo.searchIdentities(IdType.USER, name, ctrl);

                Set<?> results = ident.getSearchResults();
                if ((results != null) && !results.isEmpty()) {
                    if (results.size() > 1) {
                        logger.debug(method + "trovate multi occorrenze sullo UserStore per name[" + name
                                + "] e realm[" + realm + "]");
                    }
                    AMIdentity element = null;
                    for (Iterator<?> i = results.iterator(); i.hasNext();) {
                        element = (AMIdentity) i.next();
                        users.add(element);
                    }

                    logger.debug(method + "UTENTE TROVATO");
                } else
                    logger.debug(method + "nessun risultato trovato!");
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return users;
    }

    public List<AMIdentity> getUserStoreIdentityQuery(Map<String, String> searchFilter, String realm) {
        String method = "[getUserStoreIdentityQuery]:: ";

        logger.debug(
                method + " --------- ricerca utente [" + searchFilter + "] e realm[" + realm + "] ------------ ");
        List<AMIdentity> users = new ArrayList<AMIdentity>();

        if (searchFilter == null || searchFilter.isEmpty())
            return null;

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();
        AMIdentityRepository idRepo;
        try {
            idRepo = new AMIdentityRepository(realm, adminToken);

            if (idRepo != null) {
                Map<String, Set<String>> attrMap = new HashMap<String, Set<String>>();
                IdSearchControl ctrl = new IdSearchControl();
                ctrl.setAllReturnAttributes(true);
                // ctrl.setRecursive(true);
                for (Entry<String, String> filtro : searchFilter.entrySet()) {
                    String key = filtro.getKey();
                    String value = filtro.getValue();
                    Set<String> set = new HashSet<String>();
                    set.add(value);
                    attrMap.put(key, set);
                }

                ctrl.setSearchModifiers(IdSearchOpModifier.AND, attrMap); // TODO da migliorare aggiungendo un operatore
                                                                          // nella firma del metodo
                IdSearchResults ident = idRepo.searchIdentities(IdType.USER, "*", ctrl);

                Set<?> results = ident.getSearchResults();
                if ((results != null) && !results.isEmpty()) {
                    if (results.size() > 1) {
                        logger.debug(method + "trovate pi� occorrenze sullo UserStore per searchFilter[" + searchFilter
                                + "] e realm[" + realm + "]");
                    }
                    AMIdentity element = null;
                    for (Iterator<?> i = results.iterator(); i.hasNext();) {
                        element = (AMIdentity) i.next();
                        users.add(element);
                    }

                    logger.debug(method + "UTENTE TROVATO");
                } else
                    logger.debug(method + "nessun risultato trovato!");
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return users;
    }

    public List<AMIdentity> getUserStoreIdentityQueryAnd(HashMap<String, Set<String>> searchFilter, String realm) {
        String method = "[getUserStoreIdentityQueryAnd]:: ";

        logger.debug(
                method + " --------- ricerca utente [" + searchFilter + "] e realm[" + realm + "] ------------ ");
        List<AMIdentity> users = new ArrayList<AMIdentity>();

        if (searchFilter == null || searchFilter.isEmpty())
            return null;

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();
        AMIdentityRepository idRepo;
        try {
            idRepo = new AMIdentityRepository(realm, adminToken);

            if (idRepo != null) {
                // Map<String, Set<String>> attrMap = new HashMap<String, Set<String>>();
                IdSearchControl ctrl = new IdSearchControl();
                ctrl.setAllReturnAttributes(true);
                // ctrl.setRecursive(true);
                /*
                 * for (Entry<String, String> filtro : searchFilter.entrySet()){
                 * String key = filtro.getKey();
                 * String value = filtro.getValue();
                 * Set<String> set = new HashSet<String>();
                 * set.add(value);
                 * attrMap.put(key, set);
                 * }
                 */
                ctrl.setSearchModifiers(IdSearchOpModifier.AND, searchFilter);
                IdSearchResults ident = idRepo.searchIdentities(IdType.USER, "*", ctrl);

                Set<?> results = ident.getSearchResults();
                if ((results != null) && !results.isEmpty()) {
                    if (results.size() > 1) {
                        logger.debug(method + "trovate pi� occorrenze sullo UserStore per searchFilter[" + searchFilter
                                + "] e realm[" + realm + "]");
                    }
                    AMIdentity element = null;
                    for (Iterator<?> i = results.iterator(); i.hasNext();) {
                        element = (AMIdentity) i.next();
                        users.add(element);
                    }

                    logger.debug(method + "UTENTE TROVATO");
                } else
                    logger.debug(method + "nessun risultato trovato!");
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return users;
    }

    public String getUserDN(AMIdentity user) {
        String method = "[getUserDN]:: ";
        try {
            Set<String> val = user.getAttribute("dn");
            if (val != null) {
                String[] array = val.toArray(new String[val.size()]);
                return array[0];
            } else
                logger.error(method + "user[" + user.getName() + "] - getAttribute(dn): null");
        } catch (SSOException e) {
            logger.error(method, e);
        } catch (IdRepoException e) {
            logger.error(method, e);
        }
        return null;
    }

    public String getUserStoreString(String name, String realm) {
        String method = "[getUserStoreString]:: ";

        List<AMIdentity> users = getUserStoreIdentity(name, realm);
        if (users != null && !users.isEmpty()) // utente esistente
        {
            if (users.size() > 1) {
                logger.debug(method + "trovate piu occorrenze sullo UserStore per name[" + name + "] e realm[" + realm
                        + "]");
                return null;
            } else {
                String userName = getUserDN(users.get(0));
                if (userName == null) {
                    logger.error(method + "errore GET DN USER ");
                    return null;
                }

                return userName;
            }
        }

        return null;
    }

    private boolean addUserGroups(AMIdentity user, Object[] lGroups, String realm) {
        String method = "[addUserGroups]:: ";

        if (user == null) {
            logger.error(method + "utente nullo");
            return false;
        }

        try {
            // verifica che non ci siano altri gruppi gia� associati all'utente
            String userName = getUserDN(user);
            if (userName == null) {
                logger.error(method + "errore GET DN USER ");
                return false;
            }

            Object[] dellGroups = getGroupsUsers(userName, realm);
            if (dellGroups != null && dellGroups.length > 0) {
                if (!deleteUserGroups(user, realm, dellGroups))
                    return false;
            }

            // Aggiunge i gruppi corretti
            if (lGroups != null && lGroups.length > 0) {
                for (int i = 0; i < lGroups.length; i++) {
                    AMIdentity groupIdentity = (AMIdentity) lGroups[i];
                    if (groupIdentity != null) {
                        // aggiunge l'utente al gruppo
                        groupIdentity.addMember(user);
                    }
                }
            }

        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }

        return false;
    }

    @SuppressWarnings("unused")
    private Map<String, Set<String>> setGroups(Map<String, Set<String>> attrs, Object[] lGroups) {
        String method = "[setGroups]:: ";
        Set<String> vals = new HashSet<String>();

        if (lGroups != null && lGroups.length > 0 && attrs != null) {
            try {
                for (int i = 0; i < lGroups.length; i++) {
                    AMIdentity groupIdentity = (AMIdentity) lGroups[i];
                    if (groupIdentity != null && groupIdentity.getAttribute("dn") != null) {
                        Object[] groups = groupIdentity.getAttribute("dn").toArray();
                        vals.add((String) groups[0]);
                    }
                }
                if (vals != null)
                    attrs.put(GROUP_USERATTR, vals);
            } catch (SSOException e) {
                logger.error(method + "SSOException: ", e);
            } catch (IdRepoException e) {
                logger.error(method + "IdRepoException: ", e);
            }
        }

        return attrs;
    }

    /*
     * cancellazione
     */
    private boolean deleteUser(AMIdentity user, String realm, Object[] lGroups) throws IdRepoException, SSOException {
        String method = "[deleteUser]:: ";

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            if (adminToken != null) {
                AMIdentityRepository idRepo = new AMIdentityRepository(realm, adminToken);

                if (idRepo != null && user != null) {
                    // rimuove dai gruppi collegati
                    if (lGroups != null && lGroups.length > 0) {
                        for (int i = 0; i < lGroups.length; i++) {
                            AMIdentity groupIdentity = (AMIdentity) lGroups[i];
                            if (groupIdentity != null) {
                                // aggiunge l'utente al gruppo
                                groupIdentity.removeMember(user);
                            }
                        }
                    }
                    Set<AMIdentity> vals = new HashSet<AMIdentity>();
                    vals.add(user);
                    // cancella l'entity
                    idRepo.deleteIdentities(vals);
                    return true;
                }
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    private boolean deleteUserGroups(AMIdentity user, String realm, Object[] lGroups)
            throws IdRepoException, SSOException {
        String method = "[deleteUserGroups]:: ";

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            if (adminToken != null) {
                AMIdentityRepository idRepo = new AMIdentityRepository(realm, adminToken);

                if (idRepo != null && user != null) {
                    // rimuove dai gruppi collegati
                    if (lGroups != null && lGroups.length > 0) {
                        for (int i = 0; i < lGroups.length; i++) {
                            AMIdentity groupIdentity = (AMIdentity) lGroups[i];
                            if (groupIdentity != null) {
                                // aggiunge l'utente al gruppo
                                groupIdentity.removeMember(user);
                            }
                        }
                    }
                    return true;
                }
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    public Object[] getGroupsUsers(String userID, String realm) throws IdRepoException, SSOException {
        String method = "[getGroupsUsers]:: ";

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            if (adminToken != null) {
                AMIdentityRepository idRepo = new AMIdentityRepository(realm, adminToken);

                if (idRepo != null && userID != null) {
                    Map<String, Set<String>> attrMap = new HashMap<String, Set<String>>();
                    Set<String> set = new HashSet<String>();
                    set.add(userID);
                    attrMap.put(GROUP_ATTR, set);

                    IdSearchControl isc = new IdSearchControl();
                    isc.setAllReturnAttributes(true);
                    isc.setSearchModifiers(IdSearchOpModifier.AND, attrMap);
                    IdSearchResults results = idRepo.searchIdentities(IdType.GROUP, "*", isc);
                    Set<AMIdentity> groups = results.getSearchResults();
                    if (groups != null)
                        return groups.toArray();
                } else
                    logger.error(method + " idRepo e userID NULLI");
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }

        return null;
    }

    public boolean addTemplateUsers(String name, AMIdentity user, String realm, Map<String, List<?>> attributeMap,
            boolean delete)
            throws IdRepoException, SSOException {
        String method = "[addTemplateUsers]:: ";

        {
            logger.debug(method + "parametri: name[" + name + "]");
            logger.debug(method + "parametri: user[" + user + "]");
            logger.debug(method + "parametri: realm[" + realm + "]");
            // logger.debug(method + "parametri: attributeMap[" + attributeMap + "]");
            logger.debug(method + "parametri: delete[" + delete + "]");
        }
        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            if (adminToken != null) {
                AMIdentityRepository idRepo = new AMIdentityRepository(realm, adminToken);

                if (idRepo != null) {
                    if (user != null) {
                        Object[] groupsIdentity = getGroupsUsers(getUserDN(user), realm);
                        return addUsers(name, realm, groupsIdentity, attributeMap, delete);
                    } else
                        logger.error(method + "utente nullo");
                }
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    /*
     * updateSpidUsers:
     * - name: accountID dell'utente da creare
     * - realm: specifico Realm OpenAM
     * - baseDN: in caso di creazione in un ramo differente da quello definito nel
     * DataStore altrimenti null
     * - usrContainerName: in caso di creazione in un ramo (solo container)
     * differente da quello definito nel DataStore
     * esempio: cn=users altrimenti null
     * - attributeMap: attributi LDAP da impostare
     */
    public boolean updateSpidUsers(AMIdentity usrIdentity, Map<String, List<?>> attributeMap)
            throws IdRepoException, SSOException {
        String method = "[updateSpidUsers]:: ";

        {
            logger.debug(method + "parametri: usrIdentity[" + usrIdentity + "]");
        }

        try {
            if (usrIdentity != null) {
                return updateUsers(usrIdentity, attributeMap);
            } else
                logger.error(method + "utente nullo");
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    private boolean updateUsers(AMIdentity usrIdentity, Map<String, List<?>> attributeMap)
            throws IdRepoException, SSOException {
        String method = "[updateUsers]:: ";
        {
            logger.debug(method + "parametri: usrIdentity[" + usrIdentity + "]");
        }
        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            // aggiorna l'utente

            logger.debug(method + "inizio update utente [" + usrIdentity.getName() + "]... ");

            if (attributeMap != null && !attributeMap.isEmpty()) {
                Map<String, Set<String>> attrs = new HashMap<String, Set<String>>();
                Set<String> vals = new HashSet<String>();

                // impostare da console gli attributi LDAP da gestire mappati con gli attributi
                // dell'asserzione
                for (Entry<String, List<?>> entry : attributeMap.entrySet()) {
                    String userAttr = entry.getKey();
                    if (entry.getValue() != null) {
                        vals = new HashSet<String>();
                        Object[] userVals = entry.getValue().toArray();
                        for (int i = 0; i < userVals.length; i++)
                            vals.add((String) userVals[i]);
                        Set<String> actualAttrVal = usrIdentity.getAttribute(userAttr);
                        if (!userAttr.equalsIgnoreCase("userPassword")) {
                            logger.debug(
                                    method + "userAttr[" + userAttr + "] actualAttrVal: " + actualAttrVal.toString()
                                            + " vals[ " + vals + "]");
                        }
                        if (actualAttrVal != null && !actualAttrVal.isEmpty() && !actualAttrVal.equals(vals)) {
                            // aggiornamento attributo
                            attrs.put(userAttr, vals);
                        }
                    }
                }

                if (attrs != null && !attrs.isEmpty()) {
                    // aggiornamento Identity
                    usrIdentity.setAttributes(attrs);
                    usrIdentity.store();
                    return true;
                }
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    /*
     * addSpidUsers:
     * - name: accountID dell'utente da creare
     * - realm: specifico Realm OpenAM
     * - baseDN: in caso di creazione in un ramo differente da quello definito nel
     * DataStore altrimenti null
     * - usrContainerName: in caso di creazione in un ramo (solo container)
     * differente da quello definito nel DataStore
     * esempio: cn=users altrimenti null
     * - attributeMap: attributi LDAP da impostare
     */
    public boolean addSpidUsers(String name, String realm, String baseDN, String usrContainerName,
            Map<String, List<?>> attributeMap)
            throws IdRepoException, SSOException {
        String method = "[addSpidUsers]:: ";

        {
            logger.debug(method + "parametri: name[" + name + "]");
            logger.debug(method + "parametri: realm[" + realm + "]");
            logger.debug(method + "parametri: baseDN[" + baseDN + "]");
            logger.debug(method + "parametri: usrContainerName[" + usrContainerName + "]");
        }

        try {
            if (name != null) {
                return addUsers(name, realm, baseDN, usrContainerName, attributeMap);
            } else
                logger.error(method + "utente nullo");
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    private boolean addUsers(String name, String realm, String baseDN, String usrContainerName,
            Map<String, List<?>> attributeMap)
            throws IdRepoException, SSOException {
        String method = "[addUsers]:: ";

        {
            logger.debug(method + "parametri: name[" + name + "]");
            logger.debug(method + "parametri: realm[" + realm + "]");
            logger.debug(method + "parametri: baseDN[" + baseDN + "]");
            logger.debug(method + "parametri: usrContainerName[" + usrContainerName + "]");
        }

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            // crea l'utente

            logger.debug(method + "inizio creazione utente [" + name + "]... ");

            if (attributeMap != null && !attributeMap.isEmpty()) {

                Map<String, Set<String>> attrs = new HashMap<String, Set<String>>();
                Set<String> vals = new HashSet<String>();
                // impostare da console gli attributi LDAP da gestire mappati con gli attributi
                // dell'asserzione
                for (Entry<String, List<?>> entry : attributeMap.entrySet()) {
                    String userAttr = entry.getKey();
                    if (userAttr.equalsIgnoreCase("*"))
                        break;
                    if (entry.getValue() != null) {
                        vals = new HashSet<String>();
                        Object[] userVals = entry.getValue().toArray();
                        for (int i = 0; i < userVals.length; i++) {
                            String appoVal = userVals[i].toString();
                            // vals.add((String)userVals[i]);
                            vals.add(appoVal);
                        }

                        attrs.put(userAttr, vals);
                    }
                }

                if (baseDN != null || usrContainerName != null) {

                    IdRepo idRepo = getIdRepo(realm, null, baseDN, usrContainerName);
                    String ident = idRepo.create(adminToken, IdType.USER, name, attrs);

                    logger.debug(method + "ident: name[" + name + "] ident: " + ident);
                    return true;
                } else {
                    if (adminToken != null) {
                        AMIdentityRepository idRepo = new AMIdentityRepository(realm, adminToken);
                        AMIdentity ident = idRepo.createIdentity(IdType.USER, name, attrs);

                        logger.debug(method + "ident: name[" + name + "] isExists: " + ident.isExists());
                        return true;
                    }
                }

            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    private boolean addUsers(String name, String realm, Object[] lGroups, Map<String, List<?>> attributeMap,
            boolean delete) throws IdRepoException, SSOException {
        String method = "[addUsers]:: ";
        {
            logger.debug(method + "parametri: name[" + name + "]");
            logger.debug(method + "parametri: realm[" + realm + "]");
            logger.debug(method + "parametri: lGroups[" + lGroups + "]");
            // logger.debug(method + "parametri: attributeMap[" + attributeMap + "]");
            logger.debug(method + "parametri: delete[" + delete + "]");
        }

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            if (adminToken != null) {
                AMIdentityRepository idRepo = new AMIdentityRepository(realm, adminToken);

                if (idRepo != null) {
                    // verifica se gia esiste una utenza con la stessa userID e nel caso la cancella
                    List<AMIdentity> users = getUserStoreIdentity(name, realm);
                    if (users != null && !users.isEmpty()) // utente esistente
                    {
                        if (users.size() > 1) {
                            logger.debug(method + "trovate piu occorrenze sullo UserStore per name[" + name
                                    + "] e realm[" + realm + "]");
                            return false;
                        } else {
                            if (delete) {
                                // utente da cancellare
                                deleteUser(users.get(0), realm, getGroupsUsers(getUserDN(users.get(0)), realm));
                            } else {

                                logger.debug(method + "utente gia esistente - delete FALSE: NON FA NIENTE!");
                                return true;
                            }
                        }
                    }

                    // crea l'utente

                    logger.debug(method + "inizio creazione utente [" + name + "]... ");

                    if (attributeMap != null && !attributeMap.isEmpty()) {
                        Map<String, Set<String>> attrs = new HashMap<String, Set<String>>();
                        Set<String> vals = new HashSet<String>();
                        // vals.add(PWD_VAL);
                        // attrs.put(PWD_ATTR, vals);
                        // impostare da console gli attributi LDAP da gestire mappati con gli attributi
                        // dell'asserzione
                        for (Entry<String, List<?>> entry : attributeMap.entrySet()) {
                            String userAttr = entry.getKey();
                            if (userAttr.equalsIgnoreCase("*"))
                                break;
                            if (entry.getValue() != null) {
                                vals = new HashSet<String>();
                                Object[] userVals = entry.getValue().toArray();
                                for (int i = 0; i < userVals.length; i++) {
                                    vals.add((String) userVals[i]);
                                }
                                attrs.put(userAttr, vals);
                            }
                        }
                        // attrs = setGroups(attrs, lGroups); //TODO
                        AMIdentity ident = idRepo.createIdentity(IdType.USER, name, attrs);

                        // aggiunge l'utente ai gruppi
                        addUserGroups(ident, lGroups, realm);

                        logger.debug(method + "... fine creazione utente [" + name + "]");
                        return true;
                    } else {
                        logger.error(method + " Attributi utente non valorizzati!");
                    }
                }
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    /*
     * aggiunti in caso di creazione utente in un sotto ramo del data store
     */
    public boolean addCUSTOMUser(String name, String idRepoName, String baseDN, String usrContainerName,
            String realm, Map<String, List<?>> attributeMap)
            throws IdRepoException, SSOException {
        String method = "[addCUSTOMUser]:: ";

        {
            logger.debug(method + "parametri: name[" + name + "]");
            logger.debug(method + "parametri: realm[" + realm + "]");
            logger.debug(method + "parametri: idRepoName[" + idRepoName + "]");
            logger.debug(method + "parametri: baseDN[" + baseDN + "]");
            logger.debug(method + "parametri: usrContainerName[" + usrContainerName + "]");
        }
        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        try {
            if (adminToken != null) {

                Map<String, Set<String>> attrs = new HashMap<String, Set<String>>();
                if (attributeMap != null && !attributeMap.isEmpty()) {
                    Set<String> vals = new HashSet<String>();
                    // impostare da console gli attributi LDAP da gestire mappati con gli attributi
                    // dell'asserzione
                    for (Entry<String, List<?>> entry : attributeMap.entrySet()) {
                        String userAttr = entry.getKey();
                        if (!userAttr.equalsIgnoreCase("*")) {
                            if (entry.getValue() != null) {
                                vals = new HashSet<String>();
                                Object[] userVals = entry.getValue().toArray();
                                for (int i = 0; i < userVals.length; i++)
                                    vals.add((String) userVals[i]);
                                attrs.put(userAttr, vals);
                            }
                        }
                    }
                }

                if (attrs != null && !attrs.isEmpty()) {
                    // crea l'utente
                    {
                        logger.debug(method + "inizio creazione utente [" + name + "]... ");
                    }

                    AMIdentityRepository idRepo = new AMIdentityRepository(realm, adminToken);
                    if (idRepo != null) {
                        AMIdentity ident = idRepo.createIdentity(IdType.USER, name, attrs);

                        logger.debug(method + " identita creata [" + ident.getName() + "]");
                    }

                    logger.debug(method + "... fine creazione utente [" + name + "]");
                    return true;
                }
            } else {
                logger.error(method + " Attributi utente non valorizzati!");
            }
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return false;
    }

    public Map<String, Set<String>> getCUSTOMUserAttribute(String name, String realm, String idRepoName,
            String strBaseDN, String usrContainerName, String attrNames) {
        String method = "[getCUSTOMUserAttribute]:: ";

        logger.debug(method + " --------- ricerca utente [" + name + "] e idRepoName[" + idRepoName
                + "] e attrNames[" + attrNames + "] ------------ ");

        if (adminToken == null)
            adminToken = AdminTokenAction.getInstance().run();

        Set<String> attributeValue = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        attributeValue.add(attrNames);

        try {
            IdRepo idRepo = getIdRepo(realm, idRepoName, strBaseDN, usrContainerName);
            if (idRepo != null) {
                Map<String, Set<String>> mapAttr = idRepo.getAttributes(adminToken, IdType.USER, name, attributeValue);

                // if( logger.debugEnabled() )
                // logger.debug(method + "mapAttr: " + mapAttr);
                return mapAttr;
            } else
                logger.debug(method + "nessun idRepo " + idRepoName + " trovato!");
        } catch (SSOException e) {
            logger.error(method + "SSOException: ", e);
        } catch (IdRepoException e) {
            logger.error(method + "IdRepoException: ", e);
        }
        return null;
    }

    /**
     * Constructs IdRepo plugin object and returns.
     */
    private IdRepo constructIdRepoPlugin(String orgName, String baseDN, String usrContainerName,
            Map<String, Set<String>> configMap,
            String name) throws IdRepoException, SSOException {
        String method = "[constructIdRepoPlugin]:: ";
        {
            logger.debug(method + "parametri: orgName[" + orgName + "]");
            // logger.debug(method + "parametri: configMap[" + configMap + "]");
            logger.debug(method + "parametri: name[" + name + "]");
            logger.debug(method + "parametri: baseDN[" + baseDN + "]");
            logger.debug(method + "parametri: userContainerName[" + usrContainerName + "]");
        }

        IdRepo answer = null;
        {
            logger.debug(method + "config=" + configMap.get("sunIdRepoClass"));
        }
        if (configMap == null || configMap.isEmpty()) {

            logger.warn(method + "Cannot construct with empty config data");

            return (null);
        }
        Set<?> vals = (Set<?>) configMap.get(IdConstants.ID_REPO);
        if ((vals != null) && !vals.isEmpty()) {
            String className = (String) vals.iterator().next();
            try {
                Injector injector = InjectorHolder.getInstance(Injector.class);
                DJLDAPv3RepoFactory factory = injector.getInstance(DJLDAPv3RepoFactory.class);
                answer = factory.create(orgName, name);
            } catch (Throwable ex) {
                logger.error(method + " OrgName: " + orgName + " ConfigMap: " + configMap, ex);
                throw (new IdRepoException(ex.getMessage()));
            }

            Set<String> rootSuffixVal = configMap.get(DS_SEARCH_BASE_CONF_NAME);
            if (rootSuffixVal != null) {
                Object[] aVal = rootSuffixVal.toArray();

                // ou=people
                String sPeopleContainer = "";
                Set<String> peopleContainerVal = configMap.get(DS_PEOPLE_CONTAINER_VALUE_CONF_NAME);
                Set<String> peopleContainerName = configMap.get(DS_PEOPLE_CONTAINER_NAME_CONF_NAME);
                if (peopleContainerName != null && !peopleContainerName.isEmpty() && peopleContainerVal != null
                        && !peopleContainerVal.isEmpty()) {
                    Object[] oPCName = peopleContainerName.toArray();
                    Object[] oPCVal = peopleContainerVal.toArray();
                    if (oPCName != null && oPCName.length > 0 && oPCVal != null && oPCVal.length > 0)
                        sPeopleContainer = oPCName[0] + "=" + oPCVal[0] + ",";
                }

                // Aggiunta per specifico container People Custom non definito sullo UserStore
                // da config OpenAM
                // cn=users
                String sUserContainer = null;
                if (usrContainerName != null && !usrContainerName.isEmpty()) {
                    if (usrContainerName.indexOf("=") != -1) {
                        String[] usrContainerArray = usrContainerName.split("=");
                        if (usrContainerArray.length > 0) {
                            String sUPCName = usrContainerArray[0];
                            String sUPCVal = usrContainerArray[1];
                            if (sUPCName != null && sUPCVal != null)
                                sUserContainer = sUPCName + "=" + sUPCVal + ",";
                        } else {
                            logger.error(method, "Malformed User Container Custom");
                            return null;
                        }
                    } else {
                        logger.error(method, "Malformed User Container Custom");
                        return null;
                    }
                }

                Set<String> val = new HashSet<String>();
                if (aVal[0] != null) {
                    // baseDN per esteso ...
                    if (baseDN != null && !baseDN.isEmpty()) {
                        if (sPeopleContainer != null && !sPeopleContainer.isEmpty())
                            val.add(baseDN + "," + sPeopleContainer + aVal[0]);
                        else
                            val.add(baseDN + "," + aVal[0]);
                    } else if (sUserContainer != null && !sUserContainer.isEmpty()) { // Add Custom User Container from
                                                                                      // global prop
                        val.add(sUserContainer + aVal[0]);
                    } else {
                        val.add((String) aVal[0]);
                    }
                }
                // configMap.put(SEARCH_BASE_CONF_NAME, val);
                {
                    logger.debug(method + "IdRepo base DN: " + Arrays.toString(val.toArray()));
                }
                configMap.put(DS_ORGANIZATION_NAME_CONF_NAME, val);
            }

            /*** NEW **/
            answer.initialize(configMap);

            Map<String, String> listenerConfig = new HashMap<String, String>();
            listenerConfig.put("realm", orgName);
            listenerConfig.put("plugin-name", name);
            IdRepoListener listener = new IdRepoListener();
            listener.setConfigMap(listenerConfig);

            answer.addListener(adminToken, listener);
        }
        return (answer);
    }

    @SuppressWarnings({ "unused", "unchecked" })
    private IdRepo constructIdRepoPluginNew(String orgName, String baseDN, String usrContainerName, Map configMap,
            String name) throws IdRepoException, SSOException {
        String method = "[constructIdRepoPluginNew]:: ";
        {
            logger.debug(method + "parametri: orgName[" + orgName + "]");
            logger.debug(method + "parametri: name[" + name + "]");
            logger.debug(method + "parametri: baseDN[" + baseDN + "]");
            logger.debug(method + "parametri: userContainerName[" + usrContainerName + "]");
        }

        {
            logger.debug("IdRepoPluginsCache.constructIdRepoPlugin: config=" + configMap.get("sunIdRepoClass"));
        }
        if ((configMap == null) || (configMap.isEmpty())) {

            logger.warn("IdRepoPluginsCache.constructIdRepoPlugin: Cannot construct with empty config data");

            return null;
        }
        Set<String> classNames = (Set) configMap.get("sunIdRepoClass");
        if (classNames == null) {
            return null;
        }
        IdRepo idRepo = null;
        for (String className : classNames) {
            try {
                idRepo = newIdRepo(className);
            } catch (Throwable ex) {
                logger.error(
                        "IdRepoPluginsCached.constructIdRepoPlugin OrgName: " + orgName + " ConfigMap: " + configMap,
                        ex);

                throw new IdRepoException(ex.getMessage());
            }

            Set<String> rootSuffixVal = (Set) configMap.get(DS_SEARCH_BASE_CONF_NAME);
            if (rootSuffixVal != null) {
                Object[] aVal = rootSuffixVal.toArray();

                // ou=people
                String sPeopleContainer = "";
                Set<String> peopleContainerVal = (Set) configMap.get(DS_PEOPLE_CONTAINER_VALUE_CONF_NAME);
                Set<String> peopleContainerName = (Set) configMap.get(DS_PEOPLE_CONTAINER_NAME_CONF_NAME);
                if (peopleContainerName != null && !peopleContainerName.isEmpty() && peopleContainerVal != null
                        && !peopleContainerVal.isEmpty()) {
                    Object[] oPCName = peopleContainerName.toArray();
                    Object[] oPCVal = peopleContainerVal.toArray();
                    if (oPCName != null && oPCName.length > 0 && oPCVal != null && oPCVal.length > 0)
                        sPeopleContainer = oPCName[0] + "=" + oPCVal[0] + ",";
                }

                // Aggiunta per specifico container People Custom non definito
                // sullo UserStore da config OpenAM
                // cn=users
                String sUserContainer = null;
                if (usrContainerName != null && !usrContainerName.isEmpty()) {
                    if (usrContainerName.indexOf("=") != -1) {
                        String[] usrContainerArray = usrContainerName.split("=");
                        if (usrContainerArray.length > 0) {
                            String sUPCName = usrContainerArray[0];
                            String sUPCVal = usrContainerArray[1];
                            if (sUPCName != null && sUPCVal != null)
                                sUserContainer = sUPCName + "=" + sUPCVal + ",";
                        } else {
                            logger.error(method, "Malformed User Container Custom");
                            return null;
                        }
                    } else {
                        logger.error(method, "Malformed User Container Custom");
                        return null;
                    }
                }

                Set<String> val = new HashSet<String>();
                if (aVal[0] != null) {
                    // baseDN per esteso ...
                    if (baseDN != null && !baseDN.isEmpty()) {
                        if (sPeopleContainer != null && !sPeopleContainer.isEmpty())
                            val.add(baseDN + "," + sPeopleContainer + aVal[0]);
                        else
                            val.add(baseDN + "," + aVal[0]);
                    } else if (sUserContainer != null && !sUserContainer.isEmpty()) {
                        // Add Custom User Container from globa prop
                        val.add(sUserContainer + aVal[0]);
                    } else {
                        val.add((String) aVal[0]);
                    }
                }
                // configMap.put(SEARCH_BASE_CONF_NAME, val);
                {
                    logger.debug(method + "IdRepo base DN: " + Arrays.toString(val.toArray()));
                }
                configMap.put(DS_ORGANIZATION_NAME_CONF_NAME, val);
            }

            idRepo.initialize(configMap);

            Map<String, String> listenerConfig = new HashMap();
            listenerConfig.put("realm", orgName);
            listenerConfig.put("plugin-name", name);
            IdRepoListener listener = new IdRepoListener();
            listener.setConfigMap(listenerConfig);

            idRepo.addListener(adminToken, listener);
        }
        return idRepo;
    }

    private IdRepo newIdRepo(String className)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Class thisClass = Thread.currentThread().getContextClassLoader().loadClass(className);
        IdRepo idRepo = (IdRepo) thisClass.newInstance();
        IdRepoAuditorFactory factory = (IdRepoAuditorFactory) InjectorHolder.getInstance(IdRepoAuditorFactory.class);
        return factory.create(idRepo);
    }

    /**
     * Adds an IdRepo plugin to an organization given the configuration
     *
     * @param orgName organization to which IdRepo would be added
     * @param scName  dataStore Name
     * @param baseDN  base DN for create user
     */
    private IdRepo getIdRepo(String orgName, String scName, String baseDN, String usrContainerName)
            throws IdRepoException, SSOException {
        String method = "[getIdRepo]:: ";

        {
            logger.debug(method + "called for orgName: " + orgName
                    + " IdRepo scName: " + scName + "  baseDN: " + baseDN + " usrContainerName: " + usrContainerName);
        }

        if (orgName != null) {
            // SE E' GIA ISTANZIATO VERIFICA SE RICHIEDE AGGIORNAMENTO
            // TODO

            Map<String, Set<String>> configMap = null;
            try {
                ServiceConfig sc = idRepoServiceConfigManager.getOrganizationConfig(orgName, null);
                if (sc == null) {
                    logger.error(method + " orgName: " + orgName + " does not exisit");
                    Object[] args = { orgName };
                    throw new IdRepoException(
                            IdRepoBundle.BUNDLE_NAME, "312", args);
                }

                if (scName == null || scName.isEmpty()) {
                    if (sc.getSubConfigNames() != null) {
                        String[] aScName = (String[]) sc.getSubConfigNames()
                                .toArray(new String[sc.getSubConfigNames().size()]);
                        scName = aScName[0];
                    } else {
                        logger.error(method + "DataStore name undefined for orgName: " + orgName + " sc name: "
                                + scName);

                        return null;
                    }
                }

                sc = sc.getSubConfig(scName);
                if (sc == null) {
                    logger.error(method + " orgName: " + orgName + " subConfig does not exisit: " + scName);
                    Object[] args = { orgName + ":" + scName };
                    throw new IdRepoException(IdRepoBundle.BUNDLE_NAME, "312", args);
                }
                configMap = sc.getAttributes();
            } catch (SMSException smse) {

                logger.warn(method + "SMSException " + "for orgName: " + orgName + " sc name: " + scName, smse);
                return null;
            }

            IdRepo repo = constructIdRepoPlugin(orgName, baseDN, usrContainerName, configMap, scName);

            // Add to cache
            orgName = DNUtils.normalizeDN(orgName);
            logger.debug(method + " orgName normalizeDN: " + orgName); // TODO
            // synchronized (idrepoPlugins) {
            // Map<String, IdRepo> repos = (Map<String, IdRepo>) idrepoPlugins.get(orgName);
            // boolean addInternalRepos = false;
            // if (repos == null) {
            // repos = new LinkedHashMap();
            // idrepoPlugins.put(orgName, repos);
            // addInternalRepos = true;
            // }
            // repos.put(name, repo);
            // }
            return repo;
        } else
            logger.error(method + " orgName: " + orgName + " does not exisit!");
        return null;
    }

    // MODIFICA LOG SPID AZIENDE
    /**
     * Metodo che gestisce l'aggiunta manuale degli attributi sul DS in caso i
     * utenza Company
     *
     * @param attrs, la lista che contiene coppia key-vals che saranno aggiunti nel
     *               LDAP
     */
    private void customAttributeCompany(Map<String, Set<String>> attrs) {

        String method = "[customAttributeCompany]:: ";

        {
            logger.debug(method + "aggiungo i parametri sul ds per l'utenza company");
        }

        logger.debug(method + "aggiungo i parametri sul ds per l'utenza company");

        Map<String, Set<String>> attrsCompany = new HashMap<String, Set<String>>();

        for (Entry<String, Set<String>> entry : attrs.entrySet()) {

            // MODIFICA LOG SPID AZIENDE
            logger.debug(method + "userAttr ---> " + entry.getKey());
            logger.debug(method + "vals ---> " + entry.getValue());

            // GESTIONE DEL CODICE FISCALE
            if (entry.getKey().equals("cdmCodiceFiscale")) {
                attrsCompany.put("cdmCodiceFiscaleDelegato", entry.getValue());
            }

            // GESTIONE DEL MOBILE PHONE
            if (entry.getKey().equals("mobile")) {
                attrsCompany.put("cdmMobilePhoneDelegato", entry.getValue());
            }

            // GESTIONE DELL'EMAIL
            if (entry.getKey().equals("mail")) {
                attrsCompany.put("cdmEmailDelegato", entry.getValue());
            }

            // GESTIONE DEL REGISTERED OFFICE
            if (entry.getKey().equals("cdmRegisteredOffice")) {
                attrsCompany.put("cdmRegisteredOffice", entry.getValue());
            }

            // GESTIONE DEL REGISTERED OFFICE
            if (entry.getKey().equals("cdmDomicilioDigitale")) {
                attrsCompany.put("cdmDomicilioDigitale", entry.getValue());
            }

            // GESTIONE DELLA VIA
            if (entry.getKey().equals("cdmSedeVia")) {
                attrsCompany.put("cdmSedeVia", entry.getValue());
            }

            // GESTIONE DEL CAP
            if (entry.getKey().equals("cdmSedeCAP")) {
                attrsCompany.put("cdmSedeCAP", entry.getValue());
            }

            // GESTIONE DELLA PROVINCIA
            if (entry.getKey().equals("cdmSedeProvincia")) {
                attrsCompany.put("cdmSedeProvincia", entry.getValue());
            }

            // GESTIONE DEL COMUNE
            if (entry.getKey().equals("cdmSedeComune")) {
                attrsCompany.put("cdmSedeComune", entry.getValue());
            }

        }

        attrs.putAll(attrsCompany);

    }

}
