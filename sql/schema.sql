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
	Token char(63),
	CSRFtoken char(44)
);
