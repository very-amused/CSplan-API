---- Tables
CREATE DATABASE IF NOT EXISTS CSplanGo;

-- Authentication - Users and Tokens
CREATE TABLE IF NOT EXISTS CSplanGo.Users (
	ID bigint unsigned NOT NULL,
	Email varchar(255) NOT NULL,
	Verified boolean NOT NULL DEFAULT 0,
	PRIMARY KEY (ID),
	UNIQUE KEY (Email)
);

CREATE TABLE IF NOT EXISTS CSplanGo.AuthKeys (
	UserID bigint unsigned NOT NULL,
	AuthKey blob NOT NULL,
	HashParams json NOT NULL,
	PRIMARY KEY (UserID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- User authentication and session information
CREATE TABLE IF NOT EXISTS CSplanGo.Sessions (
	ID bigint unsigned NOT NULL,
	UserID bigint unsigned NOT NULL,
	Token tinyblob NOT NULL,
	CSRFtoken tinyblob NOT NULL,
	Created bigint unsigned NOT NULL DEFAULT UNIX_TIMESTAMP(),
	LastUsed bigint unsigned NOT NULL DEFAULT UNIX_TIMESTAMP(),
	DeviceInfo tinytext NOT NULL DEFAULT '',
	PRIMARY KEY (ID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- User privacy settings
CREATE TABLE IF NOT EXISTS CSplanGo.Settings (
	UserID bigint unsigned NOT NULL,
	EnableIPLogging boolean NOT NULL DEFAULT 0,
	EnableReminders boolean NOT NULL DEFAULT 0,
	PRIMARY KEY (UserID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- Automatically create a default set of settings when a user registers their account (all privacy releases are kept off by default)
delimiter |
CREATE TRIGGER IF NOT EXISTS CSplanGo.CreateSettings
	AFTER INSERT ON CSplanGo.Users FOR EACH ROW
	BEGIN
		INSERT INTO CSplanGo.Settings (UserID) VALUES (NEW.ID);
	END |
delimiter ;

-- Tokens used for a user to confirm their account's deletion
CREATE TABLE IF NOT EXISTS CSplanGo.DeleteTokens (
	UserID bigint unsigned NOT NULL,
	Token tinytext NOT NULL,
	_Timestamp bigint unsigned NOT NULL DEFAULT UNIX_TIMESTAMP(),
	PRIMARY KEY (UserID) -- Only one deletetoken can be stored for a user at a time
);

-- Challenge's used to authenticate users
CREATE TABLE IF NOT EXISTS CSplanGo.Challenges (
  ID bigint unsigned NOT NULL,
  UserID bigint unsigned NOT NULL,
  _Data blob NOT NULL,
  Failed boolean NOT NULL DEFAULT 0,
  _Timestamp bigint unsigned NOT NULL DEFAULT UNIX_TIMESTAMP(),
  PRIMARY KEY (ID),
  FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- Cryptography management - Keys
CREATE TABLE IF NOT EXISTS CSplanGo.CryptoKeys (
	UserID bigint unsigned NOT NULL,
	PublicKey blob NOT NULL,
	PrivateKey blob NOT NULL,
	PBKDF2salt tinyblob NOT NULL,
	PRIMARY KEY (UserID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- Personalization - Names + Identifiers
CREATE TABLE IF NOT EXISTS CSplanGo.Names (
	UserID bigint unsigned NOT NULL,
	FirstName tinyblob NOT NULL DEFAULT '',
	LastName tinyblob NOT NULL DEFAULT '',
	Username tinyblob NOT NULL DEFAULT '',
	CryptoKey blob NOT NULL,
	PRIMARY KEY (UserID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- Todos - Todo lists for a user
CREATE TABLE IF NOT EXISTS CSplanGo.TodoLists (
	ID bigint unsigned NOT NULL,
	UserID bigint unsigned NOT NULL,
	Title tinyblob NOT NULL DEFAULT '',
	-- Items are stored as json with each value as encrypted base64 in order to preserve structure
	Items json NOT NULL DEFAULT '[]',
	_Index tinyint unsigned NOT NULL,
	CryptoKey blob NOT NULL,
	PRIMARY KEY (ID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

CREATE TABLE IF NOT EXISTS CSplanGo.NoList (
	UserID bigint unsigned NOT NULL,
	Items json NOT NULL DEFAULT '[]',
	CryptoKey blob NOT NULL DEFAULT '',
	PRIMARY KEY (UserID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

CREATE TABLE IF NOT EXISTS CSplanGo.Tags (
	ID bigint unsigned NOT NULL,
	UserID bigint unsigned NOT NULL,
	Name tinyblob NOT NULL DEFAULT '',
	Color tinyblob NOT NULL DEFAULT '',
	CryptoKey blob NOT NULL,
	PRIMARY KEY (ID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

CREATE TABLE IF NOT EXISTS CSplanGo.Reminders (
	ID bigint unsigned NOT NULL,
	UserID bigint unsigned NOT NULL,
	Title tinyblob NOT NULL DEFAULT '',
	RetryInterval mediumint unsigned NOT NULL DEFAULT 300 CHECK(RetryInterval <= 86400), -- How long the server should wait before retrying a failed notification in seconds (may be up to 24 hours)
	_Timestamp bigint unsigned NOT NULL DEFAULT (UNIX_TIMESTAMP() + 300),
	PRIMARY KEY (ID),
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);
