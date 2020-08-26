#! /bin/sh

# This script will completely delete the account associated with the email "user@test.com",
# using pure SQL queries. This is meant to be run in the case of API tests failing to delete the test user.

# Tables are read in reverse order to ensure that no foreign key constraints are violated
tables=$(tac sql/schema.sql | grep 'CREATE TABLE IF NOT EXISTS' | awk '{print $6}')
db=$(awk 'NR==1{split($1,a,"."); print a[1]}' <<< $tables)

queries="SELECT ID INTO @UserID FROM $db.Users WHERE Email = 'test@user2.com';"
while read table; do
	[ "$table" == "$db.Users" ] && continue
	query="DELETE FROM $table WHERE UserID = @UserID;"
	queries="$queries $query"
done <<< $tables

# Append the final delete query to the end of the statement
final_query="DELETE FROM $db.Users WHERE ID = @UserID;"
queries="$queries $final_query"

# Run the queries and notify the user of success
mariadb -uadmin -p$MARIADB_PASSWORD <<< $queries \
&& echo -e "\e[32mThe test user account has successfully been cleared from the database.\e[0m"
