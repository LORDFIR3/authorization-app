JWT Authorization App

An authoriization app that uses JWT. Basically app connects to PostgreSQL database and checks if credentials are in database, 
if yes - creates a token, sends it to redis cache (token blacklisting) and user can move forward.
