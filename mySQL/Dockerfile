FROM mysql:8.4.7
ENV MYSQL_DATABASE=Proxy_Authenticator_DB \
    MYSQL_ROOT_PASSWORD=examplepassword

ADD ./Database.sql /docker-entrypoint-initdb.d
EXPOSE 3306
