This is a boilerplate with basic configuations to quickly start development with Django Rest Framework. It uses docker to set up the running environment, with PostgreSQL and PgAdmin.

A basic custom login system is already in place with its login, password-reset, password confirm token (with default email backend), and password change form, all fully functional and designed.

# Installation
- Clone the repository or download it as a .zip file.
- Create a new file called 'dev.env' and add the following variables in it:
  # PostgreSQL database settings
  - ***POSTGRES_DB*** : name of the database in postgres
  - ***POSTGRES_USER*** : Postgres username you want.
  - ***POSTGRES_PASSWORD** : Postgres password you want.
  # PgAdmin credentials. These will be used to login into the webui for PgAdmin.
  - ***PGADMIN_DEFAULT_EMAIL*** : pgadmin username you want.
  - ***PGADMIN_DEFAULT_PASSWORD** : pgadmin password you want.
  # Django settings
  - ***secret_key*** : Secret key of the project. Value must be a long random string. [Can be generated from here.](https://djecrety.ir/)
  - ***db_user*** : PostgreSQL username. Must be same as ***POSTGRES_USER*** variable set above.
  - ***db_pass*** : PostgreSQL password. Must be same as ***POSTGRES_PASSWORD*** variable set above.
  - ***db_host*** : Must be set to 'db' only. Example; "db_host = db"
  - ***db_name*** : PostgreSQL database name. Must be same as ***POSTGRES_DB*** variable set above.
  - ***db_port*** : 5432.
  - ***DJANGO_DEVELOPMENT*** : Set to `True` to set `DEBUG = True`. In production, set this value to `False`.

- After configuring the dev.txt, just open cmd/terminal in project root and run `docker compose -f docker-compose-dev.yml up` command and everything should be up and running.
- Once logged into PgAdmin for the first time, make sure to add the PostgreSQL server. The server name should be "db". And use the ***POSTGRES_USER*** and ***POSTGRES_PASSWORD** values set in dev.txt as login credentials.
- Once db is set up in PgAdmin, create a database in it, it should be the same name as ***db_name*** variable set in dev.txt.
