-- Run if unit tests fail to revert changes

-- Clear test user info out of any tables that depend on the Users table via foreign key,
-- Then delete the test user from the Users table
SELECT ID INTO @UserID FROM CSplanGo.Users WHERE Email = "user@test.com";
DELETE FROM CSplanGo.Names WHERE UserID = @UserID;
DELETE FROM CSplanGo.TodoLists WHERE UserID = @UserID;
DELETE FROM CSplanGo.Tags WHERE UserID = @UserID;
DELETE FROM CSplanGo.Users WHERE ID = @UserID;
