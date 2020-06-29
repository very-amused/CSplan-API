-- Authentication - Users and Tokens
CREATE TABLE IF NOT EXISTS CSplanGo.Users (
	ID bigint unsigned NOT NULL,
	Email varchar(255) NOT NULL,
	Password binary(48),
	Verified boolean NOT NULL DEFAULT 0,
	PRIMARY KEY (ID),
	UNIQUE (Email)
);

CREATE TABLE IF NOT EXISTS CSplanGo.Tokens (
	UserID bigint unsigned NOT NULL,
	Token char(63) NOT NULL,
	CSRFtoken char(44) NOT NULL
);

CREATE TABLE IF NOT EXISTS CSplanGo.DeleteTokens (
	UserID bigint unsigned NOT NULL,
	Token char(43) NOT NULL,
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- Cryptography management - Keys
CREATE TABLE IF NOT EXISTS CSplanGo.CryptoKeys (
	UserID bigint unsigned NOT NULL,
	PublicKey blob NOT NULL,
	PrivateKey blob NOT NULL,
	PBKDF2salt tinyblob NOT NULL,
	FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- Personalization - Names + Identifiers
CREATE TABLE IF NOT EXISTS CSplanGo.Names (
	UserID bigint unsigned NOT NULL,
	FirstName tinyblob NOT NULL DEFAULT '',
	LastName tinyblob NOT NULL DEFAULT '',
	Username tinyblob NOT NULL DEFAULT '',
	CryptoKey blob NOT NULL,
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
