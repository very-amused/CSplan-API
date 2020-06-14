-- Authentication - Users and Tokens
CREATE TABLE IF NOT EXISTS CSplanGo.Users (
	ID bigint NOT NULL,
	Email varchar(255) NOT NULL,
	Password binary(48),
	Verified boolean NOT NULL DEFAULT 0,
	PRIMARY KEY (ID),
	UNIQUE (Email)
);

CREATE TABLE IF NOT EXISTS CSplanGo.Tokens (
	UserID bigint NOT NULL,
	Token char(63) NOT NULL,
	CSRFtoken char(44) NOT NULL
);

-- Personalization - Names + Identifiers
CREATE TABLE IF NOT EXISTS CSplanGo.Names (
	UserID bigint unsigned NOT NULL,
	FirstName varchar(255) NOT NULL DEFAULT '',
	LastName varchar(255) NOT NULL DEFAULT '',
	Username varchar(255) NOT NULL DEFAULT '',
	CryptoKey text NOT NULL,
	PRIMARY KEY (UserID),
	UNIQUE (Identifier)
);
