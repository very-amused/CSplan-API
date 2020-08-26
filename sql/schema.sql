-- Enable global event scheduler
SET GLOBAL event_scheduler = ON;

-- Authentication - Users and Tokens
CREATE TABLE IF NOT EXISTS CSplanGo.Users (
	ID bigint unsigned NOT NULL,
	Email varchar(255) NOT NULL,
	Verified boolean NOT NULL DEFAULT 0,
	PRIMARY KEY (ID),
	UNIQUE (Email)
);

-- State management
CREATE TABLE IF NOT EXISTS CSplanGo.Tokens (
	UserID bigint unsigned NOT NULL,
	Token tinytext NOT NULL,
	CSRFtoken tinytext NOT NULL
);

CREATE TABLE IF NOT EXISTS CSplanGo.DeleteTokens (
	UserID bigint unsigned NOT NULL,
	Token tinytext NOT NULL,
	_Timestamp bigint unsigned NOT NULL DEFAULT UNIX_TIMESTAMP(),
	PRIMARY KEY (UserID) -- Only one deletetoken can be stored for a user at a time
);

CREATE TABLE IF NOT EXISTS CSplanGo.Challenges (
  ID bigint unsigned NOT NULL,
  UserID bigint unsigned NOT NULL,
  _Data blob NOT NULL,
  Failed boolean DEFAULT 0,
  _Timestamp bigint unsigned NOT NULL DEFAULT UNIX_TIMESTAMP(),
  PRIMARY KEY (ID),
  FOREIGN KEY (UserID) REFERENCES CSplanGo.Users(ID)
);

-- Create event for clearing delete tokens older than 5min
delimiter |
CREATE EVENT IF NOT EXISTS CSplanGo.ClearDeleteTokens
	ON SCHEDULE EVERY 1 MINUTE
	COMMENT "Clear delete tokens older than 5 minutes."
	DO
		BEGIN
			DELETE FROM CSplanGo.DeleteTokens WHERE UNIX_TIMESTAMP() - _Timestamp > 300;
		END |

-- Create events for the management of challenge attempts
CREATE EVENT IF NOT EXISTS CSplanGo.ClearChallenges
  ON SCHEDULE EVERY 1 MINUTE
  COMMENT "Clear abandoned challenge attempts. An attempt is considered abandoned when it has not been attempted within 1 minute of being requested."
  DO
    BEGIN
      DELETE FROM CSplanGo.Challenges WHERE FAILED = 0 AND UNIX_TIMESTAMP() - _Timestamp > 60;
    END |

CREATE EVENT IF NOT EXISTS CSplanGo.ClearChallengeFails
  ON SCHEDULE EVERY 1 MINUTE
  COMMENT "Clear failed challenge attempts older than 1 hour. These are kept in the database longer for ratelimiting purposes."
  DO
    BEGIN
      DELETE FROM CSplanGo.Challenges WHERE FAILED = 1 AND UNIX_TIMESTAMP() - _Timestamp > 3600;
    END |
delimiter ;

-- Cryptography management - Keys
CREATE TABLE IF NOT EXISTS CSplanGo.CryptoKeys (
	UserID bigint unsigned NOT NULL,
	PublicKey blob NOT NULL,
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
