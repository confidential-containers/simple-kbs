#!/bin/bash

set -e

echo "+ Running: cargo fmt"
cargo fmt --all -- --check

echo "+ Running: cargo clippy"
cargo clippy -- -D warnings

SIMPLE_KBS_DIR="$(dirname $0)/.."

export KBS_DB_TYPE=mysql
export KBS_DB_HOST=127.0.0.1
export KBS_DB_USER=root
export KBS_DB_PW=root
#export KBS_DB=simple_kbs
export KBS_DB=simple_kbs_test

echo "+ Starting kbs-db-mysql DB server container..."
docker run --detach --rm \
           -p 3306:3306 \
           --name kbs-db \
           --env MARIADB_ROOT_PASSWORD=$KBS_DB_PW \
           mariadb:latest

sleep 5
echo -n "+ Trying to connect to mysql DB server..."
while true ; do
  echo -n '.'
  if mysql --silent -u${KBS_DB_USER} -p${KBS_DB_PW} -h ${KBS_DB_HOST} -e "SELECT 1;" > /dev/null 2>&1 ; then
    echo " Success!"
    break
  fi
  sleep 1
done

echo "+ Creating mysql database ${KBS_DB}"
mysql -u${KBS_DB_USER} -p${KBS_DB_PW} -h ${KBS_DB_HOST} -e "CREATE DATABASE ${KBS_DB};"
mysql -u${KBS_DB_USER} -p${KBS_DB_PW} -h ${KBS_DB_HOST} ${KBS_DB} < "${SIMPLE_KBS_DIR}/db-mysql.sql"

echo "+ Running: cargo test for mysql using mariadb:latest"
cargo test

echo "+ Stopping kbs-db-mysql DB server container..."
docker stop kbs-db


export KBS_DB_USER=postgres
export KBS_DB_PW=root
#export KBS_DB=simple_kbs
export KBS_DB_TYPE=postgresql

export POSTGRES_PASSWORD=$KBS_DB_PW \
export POSTGRES_USER=$KBS_DB_USER \
export PGPASSWORD=$KBS_DB_PW \

echo "+ Starting kbs-db-postgres DB server container..."
docker run --detach --rm \
           -p 5432:5432 \
           --name kbs-db-postgres \
           --env POSTGRES_PASSWORD=$KBS_DB_PW \
           --env POSTGRES_USER=$KBS_DB_USER \
           --env PGPASSWORD=$KBS_DB_PW \
           postgres:latest

sleep 5
echo -n "+ Trying to connect to postgres DB server..."
while true ; do
  echo -n '.'
  if psql -U ${KBS_DB_USER} -h ${KBS_DB_HOST} -c "SELECT 1;" > /dev/null 2>&1 ; then
    echo " Success!"
    break
  fi
  sleep 1
done

echo "+ Creating postgres database ${KBS_DB}"
psql -U ${KBS_DB_USER} -h ${KBS_DB_HOST} -c "CREATE DATABASE ${KBS_DB};"
psql -U ${KBS_DB_USER} -h ${KBS_DB_HOST} ${KBS_DB} < "${SIMPLE_KBS_DIR}/db-postgres.sql"

echo "+ Running: cargo test for kbs-db-postgres"
cargo test

echo "+ Stopping kbs-db-postgres DB server container..."
docker stop kbs-db-postgres

echo "+ Updating exports for sqlite testing..."


export KBS_DB_TYPE=sqlite
export KBS_DB_HOST=localhost
export KBS_DB_USER=${USER}
export KBS_DB_PW=${USER}
export KBS_DB=simple_kbs_test.db

if [ -f ${KBS_DB} ]; then
	rm -f ${KBS_DB}
fi

sqlite3 ${KBS_DB} < db-sqlite.sql 

echo "+ Running: cargo test using local sqlite"
cargo test

rm -f ${KBS_DB}
