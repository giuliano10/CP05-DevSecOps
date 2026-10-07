# Imagem oficial não privilegiada; o tag stable-alpine recebe correções upstream.
FROM docker.io/nginxinc/nginx-unprivileged:stable-alpine

COPY --chown=101:101 index.html styles.css app.js /usr/share/nginx/html/

EXPOSE 8080
