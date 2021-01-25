SET GLOBAL event_scheduler = ON;

SELECT (5 * 60) INTO @FiveMinutes;
SELECT (60 * 60) INTO @OneHour;
SELECT (14 * 24 * 60 * 60) INTO @TwoWeeks;

-- Clear sessions older than 2 weeks (and not currently in use, decided by whether the token has been active within the past hour)
delimiter |
CREATE EVENT IF NOT EXISTS CSplanGo.ClearSessions
	ON SCHEDULE EVERY 1 MINUTE
	DO
		BEGIN
			SELECT UNIX_TIMESTAMP() INTO @now;
			DELETE FROM CSplanGo.Sessions WHERE @now - Created >= @TwoWeeks AND @now - LastUsed >= @OneHour;
		END |

-- Clear delete tokens older than 5 minutes
CREATE EVENT IF NOT EXISTS CSplanGo.ClearDeleteTokens
	ON SCHEDULE EVERY 1 MINUTE
	DO
		BEGIN
			DELETE FROM CSplanGo.DeleteTokens WHERE UNIX_TIMESTAMP() - _Timestamp > @FiveMinutes;
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
