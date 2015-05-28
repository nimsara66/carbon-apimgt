-- Create Oracle New User and Connect
--------------------------------------
-- CREATE USER apimuser IDENTIFIED BY wso2; 
-- GRANT CONNECT,RESOURCE to apimuser WITH ADMIN OPTION; 
-- CONNECT apimuser/wso2
--

-- Start of IDN Tables --
CREATE TABLE IDN_BASE_TABLE (
            PRODUCT_NAME VARCHAR2 (20),
            PRIMARY KEY (PRODUCT_NAME))
/
INSERT INTO IDN_BASE_TABLE values ('WSO2 Identity Server')
/
CREATE TABLE IDN_OAUTH_CONSUMER_APPS (
            CONSUMER_KEY VARCHAR2 (512),
            CONSUMER_SECRET VARCHAR2 (512),
            USERNAME VARCHAR2 (255),
            TENANT_ID INTEGER DEFAULT 0,
            APP_NAME VARCHAR2 (255),
            OAUTH_VERSION VARCHAR2 (128),
            CALLBACK_URL VARCHAR2 (1024),
            GRANT_TYPES VARCHAR (1024),
            PRIMARY KEY (CONSUMER_KEY))
/
CREATE TABLE IDN_OAUTH1A_REQUEST_TOKEN (
            REQUEST_TOKEN VARCHAR2 (512),
            REQUEST_TOKEN_SECRET VARCHAR2 (512),
            CONSUMER_KEY VARCHAR2 (512),
            CALLBACK_URL VARCHAR2 (1024),
            SCOPE VARCHAR2(2048),
            AUTHORIZED VARCHAR2 (128),
            OAUTH_VERIFIER VARCHAR2 (512),
            AUTHZ_USER VARCHAR2 (512),
            PRIMARY KEY (REQUEST_TOKEN),
            FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE)
/
CREATE TABLE IDN_OAUTH1A_ACCESS_TOKEN (
            ACCESS_TOKEN VARCHAR2 (512),
            ACCESS_TOKEN_SECRET VARCHAR2 (512),
            CONSUMER_KEY VARCHAR2 (512),
            SCOPE VARCHAR2(2048),
            AUTHZ_USER VARCHAR2 (512),
            PRIMARY KEY (ACCESS_TOKEN),
            FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE)
/
CREATE TABLE IDN_OAUTH2_AUTHORIZATION_CODE (
            AUTHORIZATION_CODE VARCHAR2 (512),
            CONSUMER_KEY VARCHAR2 (512),
	        CALLBACK_URL VARCHAR2 (1024),
            SCOPE VARCHAR2(2048),
            AUTHZ_USER VARCHAR2 (512),
            TIME_CREATED TIMESTAMP,
            VALIDITY_PERIOD NUMBER(19),
            PRIMARY KEY (AUTHORIZATION_CODE),
            FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE)
/
CREATE TABLE IDN_OAUTH2_ACCESS_TOKEN (
			ACCESS_TOKEN VARCHAR2 (255),
			REFRESH_TOKEN VARCHAR2 (255),
			CONSUMER_KEY VARCHAR2 (255),
			AUTHZ_USER VARCHAR2 (255),
			USER_TYPE VARCHAR (25),
			TIME_CREATED TIMESTAMP,
			VALIDITY_PERIOD NUMBER(19),
			TOKEN_SCOPE VARCHAR2 (2048),
			TOKEN_STATE VARCHAR2 (25) DEFAULT 'ACTIVE',
			TOKEN_STATE_ID VARCHAR (256) DEFAULT 'NONE',
			PRIMARY KEY (ACCESS_TOKEN),
            FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE,
            CONSTRAINT CON_APP_KEY UNIQUE (CONSUMER_KEY, AUTHZ_USER,USER_TYPE,TOKEN_STATE,TOKEN_STATE_ID,TOKEN_SCOPE))
/
CREATE TABLE IDN_OAUTH2_SCOPE (
            SCOPE_ID INTEGER,
            SCOPE_KEY VARCHAR2 (100) NOT NULL,
            NAME VARCHAR2 (255) NULL,
            DESCRIPTION VARCHAR2 (512) NULL,
            TENANT_ID INTEGER DEFAULT 0 NOT NULL,
	    ROLES VARCHAR2 (500) NULL,
            PRIMARY KEY (SCOPE_ID))
/
CREATE SEQUENCE IDN_OAUTH2_SCOPE_SEQUENCE START WITH 1 INCREMENT BY 1 NOCACHE
/

CREATE OR REPLACE TRIGGER IDN_OAUTH2_SCOPE_TRIGGER
		    BEFORE INSERT
            ON IDN_OAUTH2_SCOPE
            REFERENCING NEW AS NEW
            FOR EACH ROW
            BEGIN
                SELECT IDN_OAUTH2_SCOPE_SEQUENCE.nextval INTO :NEW.SCOPE_ID FROM dual;
            END;
/
CREATE TABLE IDN_OAUTH2_RESOURCE_SCOPE (
            RESOURCE_PATH VARCHAR2 (255) NOT NULL,
            SCOPE_ID INTEGER NOT NULL,
            PRIMARY KEY (RESOURCE_PATH),
            FOREIGN KEY (SCOPE_ID) REFERENCES IDN_OAUTH2_SCOPE (SCOPE_ID) ON DELETE CASCADE
)	
/
CREATE TABLE IDN_SCIM_GROUP (
			ID INTEGER,
			TENANT_ID INTEGER NOT NULL,
			ROLE_NAME VARCHAR2(255) NOT NULL,
            ATTR_NAME VARCHAR2(1024) NOT NULL,
			ATTR_VALUE VARCHAR2(1024),
            PRIMARY KEY (ID))
/
CREATE SEQUENCE IDN_SCIM_GROUP_SEQUENCE START WITH 1 INCREMENT BY 1 NOCACHE
/

CREATE OR REPLACE TRIGGER IDN_SCIM_GROUP_TRIGGER
		    BEFORE INSERT
            ON IDN_SCIM_GROUP
            REFERENCING NEW AS NEW
            FOR EACH ROW
            BEGIN
                SELECT IDN_SCIM_GROUP_SEQUENCE.nextval INTO :NEW.ID FROM dual;
            END;
/
CREATE TABLE IDN_SCIM_PROVIDER (
            CONSUMER_ID VARCHAR(255) NOT NULL,
            PROVIDER_ID VARCHAR(255) NOT NULL,
            USER_NAME VARCHAR(255) NOT NULL,
            USER_PASSWORD VARCHAR(255) NOT NULL,
            USER_URL VARCHAR(1024) NOT NULL,
			GROUP_URL VARCHAR(1024),
			BULK_URL VARCHAR(1024),
            PRIMARY KEY (CONSUMER_ID,PROVIDER_ID))
/
CREATE TABLE IDN_OPENID_REMEMBER_ME (
            USER_NAME VARCHAR(255) NOT NULL,
            TENANT_ID INTEGER DEFAULT 0,
            COOKIE_VALUE VARCHAR(1024),
            CREATED_TIME TIMESTAMP,
            PRIMARY KEY (USER_NAME, TENANT_ID))
/
CREATE TABLE IDN_OPENID_USER_RPS (
			USER_NAME VARCHAR(255) NOT NULL,
			TENANT_ID INTEGER DEFAULT 0,
			RP_URL VARCHAR(255) NOT NULL,
			TRUSTED_ALWAYS VARCHAR(128) DEFAULT 'FALSE',
			LAST_VISIT DATE NOT NULL,
			VISIT_COUNT INTEGER DEFAULT 0,
			DEFAULT_PROFILE_NAME VARCHAR(255) DEFAULT 'DEFAULT',
			PRIMARY KEY (USER_NAME, TENANT_ID, RP_URL))
/
CREATE TABLE IDN_OPENID_ASSOCIATIONS (
			HANDLE VARCHAR(255) NOT NULL,
			ASSOC_TYPE VARCHAR(255) NOT NULL,
			EXPIRE_IN TIMESTAMP NOT NULL,
			MAC_KEY VARCHAR(255) NOT NULL,
			ASSOC_STORE VARCHAR(128) DEFAULT 'SHARED',
			PRIMARY KEY (HANDLE))
/
CREATE TABLE IDN_STS_STORE (
            ID INTEGER,
            TOKEN_ID VARCHAR(255) NOT NULL,
            TOKEN_CONTENT BLOB NOT NULL,
            CREATE_DATE TIMESTAMP NOT NULL,
            EXPIRE_DATE TIMESTAMP NOT NULL,
            STATE INTEGER DEFAULT 0,
            PRIMARY KEY (ID))
/
CREATE SEQUENCE IDN_STS_STORE_SEQUENCE START WITH 1 INCREMENT BY 1 NOCACHE
/

CREATE OR REPLACE TRIGGER IDN_STS_STORE_TRIGGER
		    BEFORE INSERT
            ON IDN_STS_STORE
            REFERENCING NEW AS NEW
            FOR EACH ROW
            BEGIN
                SELECT IDN_STS_STORE_SEQUENCE.nextval INTO :NEW.ID FROM dual;
            END;
/
CREATE TABLE IDN_IDENTITY_USER_DATA (
            TENANT_ID INTEGER DEFAULT -1234,
            USER_NAME VARCHAR(255) NOT NULL,
            DATA_KEY VARCHAR(255) NOT NULL,
            DATA_VALUE VARCHAR(255) NOT NULL,
            PRIMARY KEY (TENANT_ID, USER_NAME, DATA_KEY))
/
CREATE TABLE IDN_IDENTITY_META_DATA (
            USER_NAME VARCHAR(255) NOT NULL,
            TENANT_ID INTEGER DEFAULT -1234,
            METADATA_TYPE VARCHAR(255) NOT NULL,
            METADATA VARCHAR(255) NOT NULL,
            VALID VARCHAR(255) NOT NULL,
            PRIMARY KEY (TENANT_ID, USER_NAME, METADATA_TYPE,METADATA))
/
CREATE TABLE IDN_THRIFT_SESSION (
            SESSION_ID VARCHAR2(255) NOT NULL,
            USER_NAME VARCHAR2(255) NOT NULL,
            CREATED_TIME VARCHAR2(255) NOT NULL,
            LAST_MODIFIED_TIME VARCHAR2(255) NOT NULL,
            PRIMARY KEY (SESSION_ID)
)
/
CREATE TABLE IDN_ASSOCIATED_ID (
            ID INTEGER,
	        IDP_USER_ID VARCHAR(255) NOT NULL,
            TENANT_ID INTEGER DEFAULT -1234,
	        IDP_ID VARCHAR(255) NOT NULL,
 	        USER_NAME VARCHAR(255) NOT NULL,
	        PRIMARY KEY (ID),
            UNIQUE(IDP_USER_ID, TENANT_ID, IDP_ID)
)
/
CREATE SEQUENCE IDN_ASSOCIATED_ID_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDN_ASSOCIATED_ID_TRIG
            BEFORE INSERT
            ON IDN_ASSOCIATED_ID
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDN_ASSOCIATED_ID_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/

-- End of IDN Tables --


-- Start of IDN-APPLICATION-MGT Tables--
CREATE TABLE SP_APP (
            ID INTEGER,
            TENANT_ID INTEGER NOT NULL,
	    	APP_NAME VARCHAR (255) NOT NULL ,
	    	USER_STORE VARCHAR (255) NOT NULL,
            USERNAME VARCHAR (255) NOT NULL ,
            DESCRIPTION VARCHAR (1024),
	    	ROLE_CLAIM VARCHAR (512),
            AUTH_TYPE VARCHAR (255) NOT NULL,
	    	PROVISIONING_USERSTORE_DOMAIN VARCHAR (512),
	    	IS_LOCAL_CLAIM_DIALECT CHAR(1) DEFAULT '1',
	    	IS_SEND_LOCAL_SUBJECT_ID CHAR(1) DEFAULT '0',
	    	IS_SEND_AUTH_LIST_OF_IDPS CHAR(1) DEFAULT '0',
	    	SUBJECT_CLAIM_URI VARCHAR (512),
	    	IS_SAAS_APP CHAR(1) DEFAULT '0',
            PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_APP_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER SP_APP_TRIG
            BEFORE INSERT
            ON SP_APP
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT SP_APP_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
ALTER TABLE SP_APP ADD CONSTRAINT APPLICATION_NAME_CONSTRAINT UNIQUE(APP_NAME, TENANT_ID)
/
CREATE TABLE SP_INBOUND_AUTH (
            ID INTEGER,
	     	TENANT_ID INTEGER NOT NULL,
	     	INBOUND_AUTH_KEY VARCHAR (255) NOT NULL,
            INBOUND_AUTH_TYPE VARCHAR (255) NOT NULL,
            PROP_NAME VARCHAR (255),
            PROP_VALUE VARCHAR (1024) ,
	     	APP_ID INTEGER NOT NULL,
            PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_INBOUND_AUTH_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER SP_INBOUND_AUTH_TRIG
            BEFORE INSERT
            ON SP_INBOUND_AUTH
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT SP_INBOUND_AUTH_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
ALTER TABLE SP_INBOUND_AUTH ADD CONSTRAINT APPLICATION_ID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE
/
CREATE TABLE SP_AUTH_STEP (
            ID INTEGER,
            TENANT_ID INTEGER NOT NULL,
	     	STEP_ORDER INTEGER DEFAULT 1,
            APP_ID INTEGER NOT NULL ,
            IS_SUBJECT_STEP CHAR(1) DEFAULT '0',
            IS_ATTRIBUTE_STEP CHAR(1) DEFAULT '0',
            PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_AUTH_STEP_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER SP_AUTH_STEP_TRIG
            BEFORE INSERT
            ON SP_AUTH_STEP
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT SP_AUTH_STEP_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
ALTER TABLE SP_AUTH_STEP ADD CONSTRAINT APPLICATION_ID_CONSTRAINT_STEP FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE
/
CREATE TABLE SP_FEDERATED_IDP (
            ID INTEGER NOT NULL,
            TENANT_ID INTEGER NOT NULL,
            AUTHENTICATOR_ID INTEGER NOT NULL,
            PRIMARY KEY (ID, AUTHENTICATOR_ID))
/
ALTER TABLE SP_FEDERATED_IDP ADD CONSTRAINT STEP_ID_CONSTRAINT FOREIGN KEY (ID) REFERENCES SP_AUTH_STEP (ID) ON DELETE CASCADE
/
CREATE TABLE SP_CLAIM_MAPPING (
	    	ID INTEGER,
	    	TENANT_ID INTEGER NOT NULL,
	    	IDP_CLAIM VARCHAR (512) NOT NULL ,
            SP_CLAIM VARCHAR (512) NOT NULL ,
	   		APP_ID INTEGER NOT NULL,
	    	IS_REQUESTED VARCHAR(128) DEFAULT '0',
			DEFAULT_VALUE VARCHAR(255),
            PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_CLAIM_MAPPING_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER SP_CLAIM_MAPPING_TRIG
            BEFORE INSERT
            ON SP_CLAIM_MAPPING
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT SP_CLAIM_MAPPING_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
ALTER TABLE SP_CLAIM_MAPPING ADD CONSTRAINT CLAIMID_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE
/
CREATE TABLE SP_ROLE_MAPPING (
	    	ID INTEGER,
	    	TENANT_ID INTEGER NOT NULL,
	    	IDP_ROLE VARCHAR (255) NOT NULL ,
            SP_ROLE VARCHAR (255) NOT NULL ,
	    	APP_ID INTEGER NOT NULL,
            PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_ROLE_MAPPING_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER SP_ROLE_MAPPING_TRIG
            BEFORE INSERT
            ON SP_ROLE_MAPPING
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT SP_ROLE_MAPPING_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
ALTER TABLE SP_ROLE_MAPPING ADD CONSTRAINT ROLEID_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE
/
CREATE TABLE SP_REQ_PATH_AUTHENTICATOR (
	    	ID INTEGER,
	    	TENANT_ID INTEGER NOT NULL,
	    	AUTHENTICATOR_NAME VARCHAR (255) NOT NULL ,
	    	APP_ID INTEGER NOT NULL,
            PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_REQ_PATH_AUTH_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER SP_REQ_PATH_AUTH_TRIG
            BEFORE INSERT
            ON SP_REQ_PATH_AUTHENTICATOR
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT SP_REQ_PATH_AUTH_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
ALTER TABLE SP_REQ_PATH_AUTHENTICATOR ADD CONSTRAINT REQ_AUTH_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE
/
CREATE TABLE SP_PROVISIONING_CONNECTOR (
	    	ID INTEGER,
	    	TENANT_ID INTEGER NOT NULL,
            IDP_NAME VARCHAR (255) NOT NULL ,
	    	CONNECTOR_NAME VARCHAR (255) NOT NULL ,
	    	APP_ID INTEGER NOT NULL,
	    	IS_JIT_ENABLED CHAR(1) DEFAULT '0',
		BLOCKING CHAR(1) DEFAULT '0',
            PRIMARY KEY (ID))
/
CREATE SEQUENCE SP_PROV_CONNECTOR_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER SP_PROV_CONNECTOR_TRIG
            BEFORE INSERT
            ON SP_PROVISIONING_CONNECTOR
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT SP_PROV_CONNECTOR_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
ALTER TABLE SP_PROVISIONING_CONNECTOR ADD CONSTRAINT PRO_CONNECTOR_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE
/
CREATE TABLE IDP (
			ID INTEGER,
			TENANT_ID INTEGER,
			NAME VARCHAR(254) NOT NULL,
			IS_ENABLED CHAR(1) DEFAULT '1',
			IS_PRIMARY CHAR(1) DEFAULT '0',
			HOME_REALM_ID VARCHAR(254),
			IMAGE BLOB,
			CERTIFICATE BLOB,
			ALIAS VARCHAR(254),
			INBOUND_PROV_ENABLED CHAR (1) DEFAULT '0',
			INBOUND_PROV_USER_STORE_ID VARCHAR(254),
 			USER_CLAIM_URI VARCHAR(254),
 			ROLE_CLAIM_URI VARCHAR(254),
  			DESCRIPTION VARCHAR (1024),
 			DEFAULT_AUTHENTICATOR_NAME VARCHAR(254),
 			DEFAULT_PRO_CONNECTOR_NAME VARCHAR(254),
 			PROVISIONING_ROLE VARCHAR(128),
 			IS_FEDERATION_HUB CHAR(1) DEFAULT '0',
 			IS_LOCAL_CLAIM_DIALECT CHAR(1) DEFAULT '0',
			PRIMARY KEY (ID),
	                DISPLAY_NAME VARCHAR(254),
			UNIQUE (TENANT_ID, NAME))
/
CREATE SEQUENCE IDP_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_TRIG
            BEFORE INSERT
            ON IDP
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
INSERT INTO IDP (TENANT_ID, NAME, HOME_REALM_ID) VALUES (-1234, 'LOCAL', 'localhost')
/
CREATE TABLE IDP_ROLE (
			ID INTEGER,
			IDP_ID INTEGER,
			TENANT_ID INTEGER,
			ROLE VARCHAR(254),
			PRIMARY KEY (ID),
			UNIQUE (IDP_ID, ROLE),
			FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_ROLE_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_ROLE_TRIG
            BEFORE INSERT
            ON IDP_ROLE
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_ROLE_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_ROLE_MAPPING (
			ID INTEGER,
			IDP_ROLE_ID INTEGER,
			TENANT_ID INTEGER,
			USER_STORE_ID VARCHAR (253),
			LOCAL_ROLE VARCHAR(253),
			PRIMARY KEY (ID),
			UNIQUE (IDP_ROLE_ID, TENANT_ID, USER_STORE_ID, LOCAL_ROLE),
			FOREIGN KEY (IDP_ROLE_ID) REFERENCES IDP_ROLE(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_ROLE_MAPPING_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_ROLE_MAPPING_TRIG
            BEFORE INSERT
            ON IDP_ROLE_MAPPING
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_ROLE_MAPPING_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_CLAIM (
			ID INTEGER,
			IDP_ID INTEGER,
			TENANT_ID INTEGER,
			CLAIM VARCHAR(254),
			PRIMARY KEY (ID),
			UNIQUE (IDP_ID, CLAIM),
			FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_CLAIM_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_CLAIM_TRIG
            BEFORE INSERT
            ON IDP_CLAIM
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_CLAIM_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_CLAIM_MAPPING (
			ID INTEGER,
			IDP_CLAIM_ID INTEGER,
			TENANT_ID INTEGER,
			LOCAL_CLAIM VARCHAR(253),
		    DEFAULT_VALUE VARCHAR(255),
	    	IS_REQUESTED VARCHAR(128) DEFAULT '0',
			PRIMARY KEY (ID),
			UNIQUE (IDP_CLAIM_ID, TENANT_ID, LOCAL_CLAIM),
			FOREIGN KEY (IDP_CLAIM_ID) REFERENCES IDP_CLAIM(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_CLAIM_MAPPING_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_CLAIM_MAPPING_TRIG
            BEFORE INSERT
            ON IDP_CLAIM_MAPPING
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_CLAIM_MAPPING_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_AUTHENTICATOR (
            ID INTEGER,
            TENANT_ID INTEGER,
            IDP_ID INTEGER,
            NAME VARCHAR(255) NOT NULL,
            IS_ENABLED CHAR (1) DEFAULT '1',
            DISPLAY_NAME VARCHAR(255),
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, IDP_ID, NAME),
            FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_AUTHENTICATOR_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_AUTHENTICATOR_TRIG
            BEFORE INSERT
            ON IDP_AUTHENTICATOR
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_AUTHENTICATOR_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
INSERT INTO IDP_AUTHENTICATOR (TENANT_ID, IDP_ID, NAME) VALUES (-1234, 1, 'saml2sso')
/
CREATE TABLE IDP_AUTHENTICATOR_PROPERTY (
            ID INTEGER,
            TENANT_ID INTEGER,
            AUTHENTICATOR_ID INTEGER,
            PROPERTY_KEY VARCHAR(255) NOT NULL,
            PROPERTY_VALUE VARCHAR(2047),
            IS_SECRET CHAR (1) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, AUTHENTICATOR_ID, PROPERTY_KEY),
            FOREIGN KEY (AUTHENTICATOR_ID) REFERENCES IDP_AUTHENTICATOR(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_AUTHENTICATOR_PROP_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_AUTHENTICATOR_PROP_TRIG
            BEFORE INSERT
            ON IDP_AUTHENTICATOR_PROPERTY
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_AUTHENTICATOR_PROP_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_PROVISIONING_CONFIG (
            ID INTEGER,
            TENANT_ID INTEGER,
            IDP_ID INTEGER,
            PROVISIONING_CONNECTOR_TYPE VARCHAR(255) NOT NULL,
            IS_ENABLED CHAR (1) DEFAULT '0',
            IS_BLOCKING CHAR (1) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, IDP_ID, PROVISIONING_CONNECTOR_TYPE),
            FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_PROVISIONING_CONFIG_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_PROVISIONING_CONFIG_TRIG
            BEFORE INSERT
            ON IDP_PROVISIONING_CONFIG
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_PROVISIONING_CONFIG_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_PROV_CONFIG_PROPERTY (
            ID INTEGER,
            TENANT_ID INTEGER,
            PROVISIONING_CONFIG_ID INTEGER,
            PROPERTY_KEY VARCHAR(255) NOT NULL,
            PROPERTY_VALUE VARCHAR(2048),
            PROPERTY_BLOB_VALUE BLOB,
            PROPERTY_TYPE CHAR(32) NOT NULL,
            IS_SECRET CHAR (1) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, PROVISIONING_CONFIG_ID, PROPERTY_KEY),
            FOREIGN KEY (PROVISIONING_CONFIG_ID) REFERENCES IDP_PROVISIONING_CONFIG(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_PROV_CONFIG_PROP_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_PROV_CONFIG_PROP_TRIG
            BEFORE INSERT
            ON IDP_PROV_CONFIG_PROPERTY
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_PROV_CONFIG_PROP_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_PROVISIONING_ENTITY (
            ID INTEGER,
            PROVISIONING_CONFIG_ID INTEGER,
            ENTITY_TYPE VARCHAR(255) NOT NULL,
            ENTITY_LOCAL_USERSTORE VARCHAR(255) NOT NULL,
            ENTITY_NAME VARCHAR(255) NOT NULL,
            ENTITY_VALUE VARCHAR(255),
            TENANT_ID INTEGER,
            PRIMARY KEY (ID),
            UNIQUE (ENTITY_TYPE, TENANT_ID, ENTITY_LOCAL_USERSTORE, ENTITY_NAME),
            UNIQUE (PROVISIONING_CONFIG_ID, ENTITY_TYPE, ENTITY_VALUE),
            FOREIGN KEY (PROVISIONING_CONFIG_ID) REFERENCES IDP_PROVISIONING_CONFIG(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_PROV_ENTITY_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_PROV_ENTITY_TRIG
            BEFORE INSERT
            ON IDP_PROVISIONING_ENTITY
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_PROV_ENTITY_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/
CREATE TABLE IDP_LOCAL_CLAIM (
            ID INTEGER,
            TENANT_ID INTEGER,
            IDP_ID INTEGER,
            CLAIM_URI VARCHAR(255) NOT NULL,
            DEFAULT_VALUE VARCHAR(255),
	        IS_REQUESTED VARCHAR(128) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, IDP_ID, CLAIM_URI),
            FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE)
/
CREATE SEQUENCE IDP_LOCAL_CLAIM_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER IDP_LOCAL_CLAIM_TRIG
            BEFORE INSERT
            ON IDP_LOCAL_CLAIM
            REFERENCING NEW AS NEW
            FOR EACH ROW
               BEGIN
                   SELECT IDP_LOCAL_CLAIM_SEQ.nextval INTO :NEW.ID FROM dual;
               END;
/

-- End of IDN-APPLICATION-MGT Tables--


-- Start of API-MGT Tables--
CREATE TABLE AM_SUBSCRIBER (
    SUBSCRIBER_ID INTEGER,
    USER_ID VARCHAR2(50) NOT NULL,
    TENANT_ID INTEGER NOT NULL,
    EMAIL_ADDRESS VARCHAR2(256) NULL,
    DATE_SUBSCRIBED DATE NOT NULL,
    PRIMARY KEY (SUBSCRIBER_ID),
    UNIQUE (TENANT_ID,USER_ID)
)
/

CREATE SEQUENCE AM_SUBSCRIBER_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_SUBSCRIBER_TRIGGER
		            BEFORE INSERT
                    ON AM_SUBSCRIBER
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_SUBSCRIBER_SEQUENCE.nextval INTO :NEW.SUBSCRIBER_ID FROM dual;
                    END;
/
-- TODO: Have to add ON UPDATE CASCADE for the FOREIGN KEY(SUBSCRIBER_ID) relation
CREATE TABLE AM_APPLICATION (
    APPLICATION_ID INTEGER,
    NAME VARCHAR2(100),
    SUBSCRIBER_ID INTEGER,
    APPLICATION_TIER VARCHAR2(50) DEFAULT 'Unlimited',
    CALLBACK_URL VARCHAR2(512),
    DESCRIPTION VARCHAR2(512),
	APPLICATION_STATUS VARCHAR2(50) DEFAULT 'APPROVED',
    FOREIGN KEY(SUBSCRIBER_ID) REFERENCES AM_SUBSCRIBER(SUBSCRIBER_ID) ON DELETE CASCADE,
    PRIMARY KEY(APPLICATION_ID),
    UNIQUE (NAME,SUBSCRIBER_ID)
)
/

CREATE SEQUENCE AM_APPLICATION_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_APPLICATION_TRIGGER
		            BEFORE INSERT
                    ON AM_APPLICATION
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_APPLICATION_SEQUENCE.nextval INTO :NEW.APPLICATION_ID FROM dual;
                    END;
/

CREATE TABLE AM_API (
    API_ID INTEGER,
    API_PROVIDER VARCHAR2(256),
    API_NAME VARCHAR2(256),
    API_VERSION VARCHAR2(30),
    CONTEXT VARCHAR2(256),
    CONTEXT_TEMPLATE VARCHAR2(256),
    PRIMARY KEY(API_ID),
    UNIQUE (API_PROVIDER,API_NAME,API_VERSION)
)
/

CREATE SEQUENCE AM_API_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_API_TRIGGER
		            BEFORE INSERT
                    ON AM_API
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_API_SEQUENCE.nextval INTO :NEW.API_ID FROM dual;
                    END;
/

CREATE TABLE AM_API_URL_MAPPING (
    URL_MAPPING_ID INTEGER,
    API_ID INTEGER NOT NULL,
    HTTP_METHOD VARCHAR(20) NULL,
    AUTH_SCHEME VARCHAR(50) NULL,
    URL_PATTERN VARCHAR(512) NULL,
    THROTTLING_TIER varchar(512) DEFAULT NULL,
    MEDIATION_SCRIPT BLOB,
    PRIMARY KEY(URL_MAPPING_ID)
)
/

CREATE SEQUENCE AM_API_URL_MAPPING_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_API_URL_MAPPING_TRIGGER
		            BEFORE INSERT
                    ON AM_API_URL_MAPPING
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_API_URL_MAPPING_SEQUENCE.nextval INTO :NEW.URL_MAPPING_ID FROM dual;
                    END;
/

-- TODO: Have to add ON UPDATE CASCADE for the FOREIGN KEY(SUBSCRIPTION_ID) relation
CREATE TABLE AM_SUBSCRIPTION (
    SUBSCRIPTION_ID INTEGER,
    TIER_ID VARCHAR2(50),
    API_ID INTEGER,
    LAST_ACCESSED DATE NULL,
    APPLICATION_ID INTEGER,
    SUB_STATUS VARCHAR(50),
    SUBS_CREATE_STATE VARCHAR(50) DEFAULT 'SUBSCRIBE',
    FOREIGN KEY(APPLICATION_ID) REFERENCES AM_APPLICATION(APPLICATION_ID) ON DELETE CASCADE,
    FOREIGN KEY(API_ID) REFERENCES AM_API(API_ID) ON DELETE CASCADE,
    PRIMARY KEY (SUBSCRIPTION_ID)
)
/

CREATE SEQUENCE AM_SUBSCRIPTION_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_SUBSCRIPTION_TRIGGER
		            BEFORE INSERT
                    ON AM_SUBSCRIPTION
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_SUBSCRIPTION_SEQUENCE.nextval INTO :NEW.SUBSCRIPTION_ID FROM dual;
                    END;
/
-- TODO: Have to add ON UPDATE CASCADE for the FOREIGN KEY(APPLICATION_ID) and FOREIGN KEY(API_ID) relations
CREATE TABLE AM_SUBSCRIPTION_KEY_MAPPING (
    SUBSCRIPTION_ID INTEGER,
    ACCESS_TOKEN VARCHAR2(512),
    KEY_TYPE VARCHAR2(512) NOT NULL,
    FOREIGN KEY(SUBSCRIPTION_ID) REFERENCES AM_SUBSCRIPTION(SUBSCRIPTION_ID) ON DELETE CASCADE,
    PRIMARY KEY(SUBSCRIPTION_ID,ACCESS_TOKEN)
)
/
--TODO: Have to add ON UPDATE CASCADE for the FOREIGN KEY(APPLICATION_ID) relation
CREATE TABLE AM_APPLICATION_KEY_MAPPING (
    APPLICATION_ID INTEGER,
    CONSUMER_KEY VARCHAR2(512),
    KEY_TYPE VARCHAR2(512) NOT NULL,
    STATE VARCHAR2(30) NOT NULL,
    FOREIGN KEY(APPLICATION_ID) REFERENCES AM_APPLICATION(APPLICATION_ID) ON DELETE CASCADE,
    PRIMARY KEY(APPLICATION_ID,KEY_TYPE)
)
/

CREATE TABLE AM_APPLICATION_REGISTRATION (
    REG_ID INTEGER ,
    SUBSCRIBER_ID INTEGER,
    WF_REF VARCHAR2(255) NOT NULL,
    APP_ID INTEGER,
    TOKEN_TYPE VARCHAR2(30),
    TOKEN_SCOPE VARCHAR2(256) DEFAULT 'default',
    ALLOWED_DOMAINS VARCHAR2(256),
    VALIDITY_PERIOD NUMBER(19),
    UNIQUE (SUBSCRIBER_ID,APP_ID,TOKEN_TYPE),
    FOREIGN KEY(SUBSCRIBER_ID) REFERENCES AM_SUBSCRIBER(SUBSCRIBER_ID),
    FOREIGN KEY(APP_ID) REFERENCES AM_APPLICATION(APPLICATION_ID),
    PRIMARY KEY (REG_ID)
)
/
-- TODO: Have to add ON UPDATE CASCADE for the FOREIGN KEY(API_ID) relation
CREATE TABLE AM_API_LC_EVENT (
    EVENT_ID INTEGER,
    API_ID INTEGER NOT NULL,
    PREVIOUS_STATE VARCHAR2(50),
    NEW_STATE VARCHAR2(50) NOT NULL,
    USER_ID VARCHAR2(50) NOT NULL,
    TENANT_ID INTEGER NOT NULL,
    EVENT_DATE DATE NOT NULL,
    FOREIGN KEY(API_ID) REFERENCES AM_API(API_ID) ON DELETE CASCADE,
    PRIMARY KEY (EVENT_ID)
)
/

CREATE TABLE AM_APP_KEY_DOMAIN_MAPPING (
    CONSUMER_KEY VARCHAR(255),
    AUTHZ_DOMAIN VARCHAR(255) DEFAULT 'ALL',
    PRIMARY KEY (CONSUMER_KEY,AUTHZ_DOMAIN)

)
/

CREATE TABLE AM_API_COMMENTS (
    COMMENT_ID INTEGER,
    COMMENT_TEXT VARCHAR2(512),
    COMMENTED_USER VARCHAR2(255),
    DATE_COMMENTED DATE NOT NULL,
    API_ID INTEGER NOT NULL,
    FOREIGN KEY(API_ID) REFERENCES AM_API(API_ID) ON DELETE CASCADE,
    PRIMARY KEY (COMMENT_ID)
)
/

CREATE SEQUENCE AM_API_COMMENTS_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_API_COMMENTS_TRIGGER
		            BEFORE INSERT
                    ON AM_API_COMMENTS
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_API_COMMENTS_SEQUENCE.nextval INTO :NEW.COMMENT_ID FROM dual;
                    END;
/

CREATE TABLE AM_API_RATINGS (
    RATING_ID INTEGER,
    API_ID INTEGER,
    RATING INTEGER,
    SUBSCRIBER_ID INTEGER,
    FOREIGN KEY(API_ID) REFERENCES AM_API(API_ID) ON DELETE CASCADE,
    FOREIGN KEY(SUBSCRIBER_ID) REFERENCES AM_SUBSCRIBER(SUBSCRIBER_ID) ON DELETE CASCADE,
    PRIMARY KEY (RATING_ID)
)
/

CREATE SEQUENCE AM_API_RATINGS_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_API_RATINGS_TRIGGER
		            BEFORE INSERT
                    ON AM_API_RATINGS
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_API_RATINGS_SEQUENCE.nextval INTO :NEW.RATING_ID FROM dual;
                    END;
/

CREATE TABLE AM_TIER_PERMISSIONS (
    TIER_PERMISSIONS_ID INTEGER,
    TIER VARCHAR2(50) NOT NULL,
    PERMISSIONS_TYPE VARCHAR2(50) NOT NULL,
    ROLES VARCHAR2(512) NOT NULL,
    TENANT_ID INTEGER NOT NULL,
    PRIMARY KEY(TIER_PERMISSIONS_ID)
)
/

CREATE SEQUENCE AM_TIER_PERMISSIONS_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_TIER_PERMISSIONS_TRIGGER
		            BEFORE INSERT
                    ON AM_TIER_PERMISSIONS
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_TIER_PERMISSIONS_SEQUENCE.nextval INTO :NEW.TIER_PERMISSIONS_ID FROM dual;
                    END;
/

CREATE SEQUENCE AM_API_LC_EVENT_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_API_LC_EVENT_TRIGGER
		            BEFORE INSERT
                    ON AM_API_LC_EVENT
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_API_LC_EVENT_SEQUENCE.nextval INTO :NEW.EVENT_ID FROM dual;
                    END;
/
-- Start of IDP-APPLICATION-MGT Tables --

-- End of IDP-APPLICATION-MGT Tables --


CREATE TABLE AM_EXTERNAL_STORES (
    APISTORE_ID INTEGER,
    API_ID INTEGER,
    STORE_ID VARCHAR2(255) NOT NULL,
    STORE_DISPLAY_NAME VARCHAR2(255) NOT NULL,
    STORE_ENDPOINT VARCHAR2(255) NOT NULL,
    STORE_TYPE VARCHAR2(255) NOT NULL,
    FOREIGN KEY(API_ID) REFERENCES AM_API(API_ID) ON DELETE CASCADE,
    PRIMARY KEY (APISTORE_ID)
)
/

CREATE TABLE AM_WORKFLOWS(
    WF_ID INTEGER,
    WF_REFERENCE VARCHAR(255) NOT NULL,
    WF_TYPE VARCHAR(255) NOT NULL,
    WF_STATUS VARCHAR(255) NOT NULL,
    WF_CREATED_TIME TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    WF_UPDATED_TIME TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    WF_STATUS_DESC VARCHAR(1000),
    TENANT_ID INTEGER,
    TENANT_DOMAIN VARCHAR(255),
    WF_EXTERNAL_REFERENCE VARCHAR(255) NOT NULL UNIQUE,
    PRIMARY KEY (WF_ID)
)
/

CREATE TABLE AM_API_SCOPES (
   API_ID  INTEGER NOT NULL,
   SCOPE_ID  INTEGER NOT NULL,
   FOREIGN KEY (API_ID) REFERENCES AM_API (API_ID) ON DELETE CASCADE,
   FOREIGN KEY (SCOPE_ID) REFERENCES IDN_OAUTH2_SCOPE (SCOPE_ID) ON DELETE CASCADE
)
/
CREATE SEQUENCE AM_APP_REGISTRATION_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_APP_REGISTRATION_TRIGGER
		            BEFORE INSERT
                    ON AM_APPLICATION_REGISTRATION
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_APP_REGISTRATION_SEQUENCE.nextval INTO :NEW.REG_ID FROM dual;
                    END;
/

CREATE SEQUENCE AM_WORKFLOWS_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_WORKFLOWS_TRIGGER
		            BEFORE INSERT
                    ON AM_WORKFLOWS
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_WORKFLOWS_SEQUENCE.nextval INTO :NEW.WF_ID FROM dual;
                    END;
/

CREATE SEQUENCE AM_EXTERNAL_STORES_SEQUENCE START WITH 1 INCREMENT BY 1
/

CREATE OR REPLACE TRIGGER AM_EXTERNAL_STORES_TRIGGER
		            BEFORE INSERT
                    ON AM_EXTERNAL_STORES
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_EXTERNAL_STORES_SEQUENCE.nextval INTO :NEW.APISTORE_ID FROM dual;
                    END;
/

CREATE TABLE AM_API_DEFAULT_VERSION (
            DEFAULT_VERSION_ID NUMBER, 
            API_NAME VARCHAR(256) NOT NULL ,
            API_PROVIDER VARCHAR(256) NOT NULL , 
            DEFAULT_API_VERSION VARCHAR(30) , 
            PUBLISHED_DEFAULT_API_VERSION VARCHAR(30) ,
            PRIMARY KEY (DEFAULT_VERSION_ID)
)
/
CREATE SEQUENCE AM_API_DEFAULT_VERSION_SEQ START WITH 1 INCREMENT BY 1 NOCACHE
/
CREATE OR REPLACE TRIGGER AM_API_DEFAULT_VERSION_TRG
                    BEFORE INSERT
                    ON AM_API_DEFAULT_VERSION
                    REFERENCING NEW AS NEW
                    FOR EACH ROW
                    BEGIN
                    SELECT AM_API_DEFAULT_VERSION_SEQ.nextval INTO :NEW.DEFAULT_VERSION_ID FROM dual;
                    END;
/
CREATE INDEX IDX_SUB_APP_ID ON AM_SUBSCRIPTION (APPLICATION_ID, SUBSCRIPTION_ID)
/

