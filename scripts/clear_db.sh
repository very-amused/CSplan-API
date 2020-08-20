#! /bin/sh

# Tables are read in reverse order to ensure that no foreign key constraints are violated
tables=$(tac sql/schema.sql | grep 'CREATE TABLE IF NOT EXISTS' | awk '{print $6}')

queries=''
while read table; do
	query="DROP TABLE IF EXISTS $table;"
	queries="$queries $query"
done <<< $tables

mariadb -uadmin -p$MARIADB_PASSWORD <<< $queries \
&& echo -e "\e[32mThe database has been successfully cleared.\e[0m"

# If a reload (total re-creation of the database) is requested, perform it
if [ "$1" == "-reload" ]; then
	mariadb -uadmin -p$MARIADB_PASSWORD < sql/schema.sql \
	&& echo -e "\e[32mThe database has successfully been reloaded.\e[0m"
fi
