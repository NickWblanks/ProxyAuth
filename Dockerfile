FROM nginx:latest
COPY ./nginx.conf /etc/nginx/conf.d/default.conf
COPY ./DummyWebsite/ /etc/nginx/html/dummy-site
COPY ./Frontend/ /etc/nginx/html/login
