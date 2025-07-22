package com.sun.identity.custom.util;
//import java.nio.charset.StandardCharsets;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.iplanet.log.ConnectionException;
import com.iplanet.log.DriverLoadException;
import com.iplanet.log.NullLocationException;
import com.sun.identity.log.AMLogException;
import com.sun.identity.log.LogConstants;
import com.sun.identity.log.LogManager;
import com.sun.identity.log.LogManagerUtil;
import com.sun.identity.log.handlers.FormatterInitException;
import com.sun.identity.log.spi.Debug;

public class CustomHandler {
	private LogManager lmanager = LogManagerUtil.getLogManager();
    private String driver;
    private String databaseURL;
    private String tableName = "SPID_TABLE";
    private String userName;
    private String password;

	private boolean isMySQL = false;

//    private String oraDataType;
//    private String mysqlDataType;
	
	private Connection connection;

	private static com.sun.identity.shared.debug.Debug debug = null;
	private static String DBGNAME = "SPIDHandler";
	private static final DateFormat formatter = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US);
	
	public static final String col_time = "TIME";
	public static final String col_spid_id = "spid_id";
	public static final String col_authn_request = "authn_request";
	public static final String col_response = "response";
	public static final String col_authnreq_id = "authnreq_id";
	public static final String col_authnreq_issue_instant = "authnreq_issue_instant";
	public static final String col_resp_id = "resp_id";
	public static final String col_resp_issue_instant = "resp_issue_instant";
	public static final String col_resp_issuer = "resp_issuer";
	public static final String col_assertion_id = "assertion_id";
	public static final String col_assertion_subject = "assertion_subject";
	public static final String col_assertion_subject_namequalifier = "assertion_subject_nqf";
	public static final String col_fiscalcode = "fiscalcode";
	public static final String col_statuscode = "statuscode";
	public static final String col_statuscode_message = "statuscode_message";

	/**
	 * Creates a new DbHandler for a mysql database
	 * @param server host/ip of the server where mysql is running
	 * @param db mysql database name
	 * @param user username
	 * @param password password for the jdbc connection
	 * @throws ClassNotFoundException if mysql jdbc driver not in classpath
	 */
	public CustomHandler() throws ClassNotFoundException {
		if (debug == null){
			debug = com.sun.identity.shared.debug.Debug.getInstance(DBGNAME);
		}

		try {
			configure();
		} catch (NullLocationException e) {
			e.printStackTrace();
		} catch (FormatterInitException e) {
			e.printStackTrace();
		}
	}

    private void configure() throws NullLocationException, FormatterInitException {
//        oraDataType = lmanager.getProperty(LogConstants.ORA_DBDATA_FIELDTYPE);
//        mysqlDataType = lmanager.getProperty(LogConstants.MYSQL_DBDATA_FIELDTYPE);

        //TODO
//        if(lmanager.isDbUrlEnable())//addDBurl
//            databaseURL = lmanager.getProperty(LogConstants.DB_URL); //addDBurl
//        else //addDBurl
        	databaseURL = lmanager.getProperty(LogConstants.LOG_LOCATION); 
        if ((databaseURL == null) || (databaseURL.length() == 0)) {
            throw new NullLocationException("Database URL location is null");
        }

        userName = lmanager.getProperty(LogConstants.DB_USER);
        if ((userName == null) || (userName.length() == 0)) {
            throw new NullLocationException("userName is null");
        }
        password = lmanager.getProperty(LogConstants.DB_PASSWORD);
        if ((password == null) || (password.length() == 0)) {
            throw new NullLocationException("password not provided");
        }
        driver = lmanager.getProperty(LogConstants.DB_DRIVER);
        if ((driver == null) || (driver.length() == 0)) {
            throw new NullLocationException("driver not provided");
        }
        //
        //  don't know about drivers other than Oracle and MySQL
        //
        if (driver.toLowerCase().indexOf("oracle") != -1){
            isMySQL = false;
        } else if (driver.toLowerCase().indexOf("mysql") != -1) {
            isMySQL = true;
        } else {
            isMySQL = false;
            Debug.warning(tableName + ":DBHandler:configure:assuming driver: '" + driver + "' is Oracle-compatible.");
        }

    }

	/**
	 * connect to the database
	 * @throws SQLException
	 */
	public void connect() throws SQLException {
		String method = "[connect]:: ";
		
        try {
			Class.forName(driver);
			connection = DriverManager.getConnection(databaseURL, userName, password);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			if(debug.errorEnabled())
				debug.error(method + "ClassNotFoundException: " + e.getMessage());
		}
	}

	/**
	 * creates the table "mytable" on the database
	 * SOLO PER MEMO ... e solo MYSQL!
	 * @throws SQLException
	 */
	@SuppressWarnings("unused")
	private void createMyTable() throws SQLException {
		
		Statement statement = connection.createStatement();
		String table = "CREATE TABLE " + tableName +" ( "
				+ "spid_id INT NOT NULL AUTO_INCREMENT, "
				+ "time DATE, "
				+ "authn_request BLOB(8000), "
				+ "response BLOB, "
				+ "authnreq_id VARCHAR(43), "
				+ "authnreq_issue_instant DATE, "
				+ "resp_id VARCHAR(43), "
				+ "resp_issue_instant DATE, "
				+ "resp_issuer VARCHAR(255), "
				+ "assertion_id VARCHAR(43), "
				+ "assertion_subject VARCHAR(255), "
				+ "assertion_subject_nqf VARCHAR(40), "
				+ "fiscalcode VARCHAR(255), "
				+ "statuscode VARCHAR(255), "
				+ "statuscode_message VARCHAR(255), "
				+ "PRIMARY KEY ( spid_id ) )";

		statement.executeUpdate(table);
		statement.close();
	}

	/**
	 * inserts a new row with dummy data into the "mytable" table
	 * @throws SQLException
	 */
	public void insertRow(Map<?, ?> col_val) throws SQLException {
		String method = "[insertRow]:: ";
		
		if(col_val==null || col_val.size()==0){
			if(debug.messageEnabled())
				debug.message(method + " valori non impostati");
			return;
		}
			
		if(connection==null || connection.isClosed()){
			try {
				reconnectToDatabase();
				debug.error(method + "reconnectToDatabase successful.");
			} catch (DriverLoadException dle) {
				debug.error(method + "reconnectToDatabase:DLE: " + dle.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_DRIVER + "'"	+ driver + "'");
			} catch (ConnectionException ce) {
				debug.error(method + "reconnectToDatabase:CE: " + ce.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_CONNECT_FAILED);
			}
		}

		StringBuffer insert = new StringBuffer("INSERT INTO " + tableName + "(");
		insert.append(col_time + ", ");
		insert.append(col_authn_request + ", ");
		insert.append(col_response + ", ");
		insert.append(col_authnreq_id + ", ");
		insert.append(col_authnreq_issue_instant + ", ");
		insert.append(col_resp_id + ", ");
		insert.append(col_resp_issue_instant + ", ");
		insert.append(col_resp_issuer + ", ");
		insert.append(col_assertion_id + ", ");
		insert.append(col_assertion_subject + ", ");
		insert.append(col_assertion_subject_namequalifier);
		
		if( col_val.get(col_fiscalcode) != null || col_val.get(col_statuscode) != null || col_val.get(col_statuscode_message) != null  ){
			insert.append(", " + col_fiscalcode);
			insert.append(", " + col_statuscode);
			insert.append(", " + col_statuscode_message);
			insert.append( ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)" );
		}else{
			insert.append( ") VALUES(?,?,?,?,?,?,?,?,?,?,?)" );
		}
		
    	if( debug.messageEnabled() )
    		debug.message(method + "insert[ " + insert.toString() +" ]");

		PreparedStatement ps = connection.prepareStatement(insert.toString());

		try {
			// col_time
			java.util.Date today = new java.util.Date();
			java.sql.Timestamp timestamp = new java.sql.Timestamp(today.getTime());
			ps.setTimestamp(1, timestamp);

			// col_authn_request
			if (col_val.get(col_authn_request) != null){
				Blob authn_blob = connection.createBlob();
				authn_blob.setBytes(1, col_val.get(col_authn_request).toString().getBytes());
				ps.setBlob(2, authn_blob);
			}else
				ps.setNull(2, java.sql.Types.BLOB);

			// col_response
			if (col_val.get(col_response) != null){
				Blob response_blob = connection.createBlob();
				response_blob.setBytes(1, col_val.get(col_response).toString().getBytes());
				ps.setBlob(3, response_blob);
			}else
				ps.setNull(3, java.sql.Types.BLOB);

			if (col_val.get(col_authnreq_id) != null)
				ps.setString(4, (String) col_val.get(col_authnreq_id));
			else
				ps.setNull(4, java.sql.Types.VARCHAR);

			// col_authnreq_issue_instant *** Mon Jun 20 10:49:51 CEST 2016
			if (col_val.get(col_authnreq_issue_instant) != null)
				ps.setTimestamp( 5, (Timestamp)col_val.get(col_authnreq_issue_instant) );
			else
				ps.setNull(5, java.sql.Types.TIMESTAMP);

			if (col_val.get(col_resp_id) != null)
				ps.setString(6, (String) col_val.get(col_resp_id));
			else
				ps.setNull(6, java.sql.Types.VARCHAR);

			// col_resp_issue_instant *** Mon Jun 20 10:49:51 CEST 2016
			if (col_val.get(col_resp_issue_instant) != null)
				ps.setTimestamp( 7, (Timestamp)col_val.get(col_resp_issue_instant) );
			else
				ps.setNull(7, java.sql.Types.TIMESTAMP);

			if (col_val.get(col_resp_issuer) != null)
				ps.setString(8, (String) col_val.get(col_resp_issuer));
			else
				ps.setNull(8, java.sql.Types.VARCHAR);

			if (col_val.get(col_assertion_id) != null)
				ps.setString(9, (String) col_val.get(col_assertion_id));
			else
				ps.setNull(9, java.sql.Types.VARCHAR);

			// col_assertion_subject
//				if (col_val.get(col_assertion_subject) != null){
//					Blob assertion_subject_blob = connection.createBlob();
//					assertion_subject_blob.setBytes(1, col_val.get(col_assertion_subject).toString().getBytes());
//					ps.setBlob(9, assertion_subject_blob);
//				}else
//					ps.setNull(9, java.sql.Types.BLOB);
			if (col_val.get(col_assertion_subject) != null)
				ps.setString(10, (String) col_val.get(col_assertion_subject));
			else
				ps.setNull(10, java.sql.Types.VARCHAR);

			if (col_val.get(col_assertion_subject_namequalifier) != null)
				ps.setString(11, (String) col_val.get(col_assertion_subject_namequalifier));
			else
				ps.setNull(11, java.sql.Types.VARCHAR);

			// per compatibilità con adapter di versioni precedenti
			if( col_val.get(col_fiscalcode) != null || col_val.get(col_statuscode) != null || col_val.get(col_statuscode_message) != null  ){
				// col_fiscalcode 
				if (col_val.get(col_fiscalcode) != null)
					ps.setString(12, (String) col_val.get(col_fiscalcode));
				else
					ps.setNull(12, java.sql.Types.VARCHAR);
				
				// col_statuscode 
				if (col_val.get(col_statuscode) != null)
					ps.setString(13, (String) col_val.get(col_statuscode));
				else
					ps.setNull(13, java.sql.Types.VARCHAR);
				
				// col_statuscode_message 
				if (col_val.get(col_statuscode_message) != null)
					ps.setString(14, (String) col_val.get(col_statuscode_message));
				else
					ps.setNull(14, java.sql.Types.VARCHAR);
			}			
			ps.executeUpdate();
		} catch (Exception e) {
			if(debug.errorEnabled())
				debug.error(method, e);
		}finally{
			ps.close();
		}
	}

	/**
	 * @return the actual rowcount in the "mytable" table
	 * @throws SQLException
	 */
	public int getRowCount() throws SQLException {
		String method = "[getRowCount]:: ";
		
		if(connection==null || connection.isClosed()){
			try {
				reconnectToDatabase();
				debug.error(method + "reconnectToDatabase successful.");
			} catch (DriverLoadException dle) {
				debug.error(method + "reconnectToDatabase:DLE: " + dle.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_DRIVER + "'"	+ driver + "'");
			} catch (ConnectionException ce) {
				debug.error(method + "reconnectToDatabase:CE: " + ce.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_CONNECT_FAILED);
			}
		}
		
		Statement statement = connection.createStatement();
		ResultSet resultSet = statement.executeQuery("SELECT COUNT(*) FROM " + tableName );
		resultSet.next();
		int ret = resultSet.getInt(1);
		statement.close();
		resultSet.close();
		return ret;
	}
	
	public List<String> checkColumNames( Connection connection ) throws SQLException {
		String method = "[checkColumNames]:: ";
		
		List<String> result = new ArrayList<String>();
		ResultSet rs = null;

		if(connection==null || connection.isClosed()){
			try {
				reconnectToDatabase();
				debug.error(method + "reconnectToDatabase successful.");
			} catch (DriverLoadException dle) {
				debug.error(method + "reconnectToDatabase:DLE: " + dle.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_DRIVER + "'"	+ driver + "'");
			} catch (ConnectionException ce) {
				debug.error(method + "reconnectToDatabase:CE: " + ce.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_CONNECT_FAILED);
			}
		}

		Statement statement = connection.createStatement();
		StringBuffer sql = new StringBuffer("SELECT table_name, column_name, data_type");
		if(isMySQL)
			sql.append(" FROM INFORMATION_SCHEMA.COLUMNS");
		else
			sql.append(" FROM USER_TAB_COLUMNS");
		sql.append(" WHERE table_name = ");
		sql.append(tableName);

		if( debug.messageEnabled() )
    		debug.message(method + "sql[ " + sql.toString() +" ]");
		
		rs = statement.executeQuery(sql.toString());
		while (rs.next()) {
			try {
				
				String column_name = rs.getString("column_name");
				if ( column_name != null ) {
					result.add(column_name);
				}
			} catch (Exception e) {
				e.printStackTrace();
				if(debug.errorEnabled())
					debug.error(method + "Exception: " + e.getMessage());
			}
		}
		rs.close();
		statement.close();

		return result;
	}
	
	
	/**
	 * @return the actual row in the "SPID" table
	 * @throws SQLException
	 */
	public List<Map<String, Object>> getAllRow() throws SQLException {
		String method = "[getRow]:: ";
		
		List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
		ResultSet rs = null;

		if(connection==null || connection.isClosed()){
			try {
				reconnectToDatabase();
				debug.error(method + "reconnectToDatabase successful.");
			} catch (DriverLoadException dle) {
				debug.error(method + "reconnectToDatabase:DLE: " + dle.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_DRIVER + "'"	+ driver + "'");
			} catch (ConnectionException ce) {
				debug.error(method + "reconnectToDatabase:CE: " + ce.getMessage());
				throw new AMLogException(AMLogException.LOG_DB_CONNECT_FAILED);
			}
		}

		Statement statement = connection.createStatement();

		List<String> colNames = checkColumNames(connection);
			
		StringBuffer sql = new StringBuffer("SELECT ");
		sql.append(col_time + ", ");
		sql.append(col_spid_id + ", ");
		sql.append(col_authn_request + ", ");
		sql.append(col_response + ", ");
		sql.append(col_authnreq_id + ", ");
		sql.append(col_authnreq_issue_instant + ", ");
		sql.append(col_resp_id + ", ");
		sql.append(col_resp_issue_instant + ", ");
		sql.append(col_resp_issuer + ", ");
		sql.append(col_assertion_id + ", ");
		sql.append(col_assertion_subject + ", ");
		sql.append(col_assertion_subject_namequalifier );
		// per compatibilità con adapter di versioni precedenti
		if( colNames.contains(col_fiscalcode) && colNames.contains(col_statuscode) && colNames.contains(col_statuscode_message) ){
			sql.append(", " + col_fiscalcode + ", ");
			sql.append(col_statuscode + ", ");
			sql.append(col_statuscode_message);
		}		
		sql.append(" FROM " + tableName);

		if( debug.messageEnabled() )
    		debug.message(method + "sql[ " + sql.toString() +" ]");
		
		rs = statement.executeQuery(sql.toString());
		while (rs.next()) {
			Map<String, Object> col_val = new HashMap<String, Object>();
			try {
				
				Timestamp time = rs.getTimestamp(col_time);
				if ( time != null ) {
					col_val.put( col_time, formatter.format(time.getTime()) );
				}
				
				int spid_id = rs.getInt(col_spid_id);
				col_val.put(col_spid_id, spid_id);
				
				Blob authReq_blob = rs.getBlob(col_authn_request);
				if( authReq_blob != null )
					col_val.put(col_authn_request, new String(authReq_blob.getBytes(1, (int) authReq_blob.length()), "UTF-8"));
				else
					col_val.put( col_authn_request, "" );
					
				// col_response
				Blob response_blob = rs.getBlob(col_response);
				if ( response_blob != null )
					col_val.put(col_response, new String(response_blob.getBytes(1, (int) response_blob.length()), "UTF-8"));
				else
					col_val.put( col_response, "" );
					
				String authnreq_id = rs.getString(col_authnreq_id);
				if( authnreq_id!=null )
					col_val.put(col_authnreq_id, authnreq_id);
				else
					col_val.put( col_authnreq_id, "" );

				// col_authnreq_issue_instant *** Mon Jun 20 10:49:51 CEST 2016
				Timestamp authnreq_issue_instant = rs.getTimestamp(col_authnreq_issue_instant);
				if ( authnreq_issue_instant != null ) {
					col_val.put( col_authnreq_issue_instant, formatter.format(authnreq_issue_instant.getTime()) );
				}
				
				String resp_id = rs.getString(col_resp_id);
				if( resp_id!=null )
					col_val.put(col_resp_id, resp_id);
				else
					col_val.put( col_resp_id, "" );

				// col_resp_issue_instant *** Mon Jun 20 10:49:51 CEST 2016
				Timestamp resp_issue_instant = rs.getTimestamp(col_resp_issue_instant);
				if ( resp_issue_instant != null ) {
					col_val.put( col_resp_issue_instant, formatter.format(resp_issue_instant.getTime()) );
				}

				String resp_issuer = rs.getString(col_resp_issuer);
				if( resp_issuer!=null )
					col_val.put(col_resp_issuer, resp_issuer);
				else
					col_val.put( col_resp_issuer, "" );
				
				String assertion_id = rs.getString(col_assertion_id);
				if( assertion_id!=null )
					col_val.put(col_assertion_id, assertion_id);
				else
					col_val.put( col_assertion_id, "" );

				// col_assertion_subject
//					Blob assertion_subject_blob = rs.getBlob(col_assertion_subject);
//					if ( assertion_subject_blob != null )
//						col_val.put(col_assertion_subject, 
//								new String(assertion_subject_blob.getBytes(1, (int) assertion_subject_blob.length()), StandardCharsets.UTF_8));
//					else
//						col_val.put( col_assertion_subject, "" );
				String assertion_subject = rs.getString(col_assertion_subject);
				if( assertion_subject!=null )
					col_val.put(col_assertion_subject, assertion_subject);
				else
					col_val.put( col_assertion_subject, "" );

				String assertion_subject_namequalifier = rs.getString(col_assertion_subject_namequalifier);
				if( assertion_subject_namequalifier!=null )
					col_val.put(col_assertion_subject_namequalifier, assertion_subject_namequalifier);
				else
					col_val.put( col_assertion_subject_namequalifier, "" );

				// per compatibilità con adapter di versioni precedenti
				if( colNames.contains(col_fiscalcode) && colNames.contains(col_statuscode) && colNames.contains(col_statuscode_message) ){
					String fiscalcode = rs.getString(col_fiscalcode);
					if( fiscalcode!=null )
						col_val.put(col_fiscalcode, fiscalcode);
					else
						col_val.put( col_fiscalcode, "" );
					
					String statuscode = rs.getString(col_statuscode);
					if( statuscode!=null )
						col_val.put(col_statuscode, statuscode);
					else
						col_val.put( col_statuscode, "" );
					
					String statuscode_message = rs.getString(col_statuscode_message);
					if( statuscode_message!=null )
						col_val.put(col_statuscode_message, statuscode_message);
					else
						col_val.put( col_statuscode_message, "" );
				}
			} catch (Exception e) {
				e.printStackTrace();
				if(debug.errorEnabled())
					debug.error(method + "Exception: " + e.getMessage());
			}
			if(col_val!=null)
				result.add(col_val);
		}
		rs.close();
		statement.close();

		return result;
	}

	/**
	 * closes the connection to the database
	 * @throws SQLException
	 */
	public void close() throws SQLException {
		if(connection!=null && !connection.isClosed()){
			connection.close();
			connection = null;
		}
	}
	
    //
    //  detected that connection to the DB had failed previously;
    //  this routine reestablishes the connection, and checks that
    //  the table exists (creating it if it doesn't).
    //
    private void reconnectToDatabase() throws ConnectionException, DriverLoadException {
		String method = "[reconnectToDatabase]:: ";

        try {
            Class.forName(driver);
            this.connection = DriverManager.getConnection(databaseURL, userName, password);
        } catch (ClassNotFoundException e) {
            debug.error (method + " ClassNotFoundException: " + e.getMessage());
            throw new DriverLoadException(e.getMessage());
        } catch (SQLException sqle) {
            debug.error (method + " SQLException (" + sqle.getErrorCode() + "): " + sqle.getMessage());
            throw new ConnectionException(sqle.getMessage());
        }
    }

}
