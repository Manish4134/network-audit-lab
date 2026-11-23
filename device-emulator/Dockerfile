FROM python:3.12-alpine
RUN apk add --no-cache openssh-server && \
    ssh-keygen -A && \
    rm -f /etc/motd && \
    adduser -D -s /usr/local/bin/mock_cli.py audit && \
    echo "audit:audit123" | chpasswd && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
COPY mock_cli.py /usr/local/bin/mock_cli.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/mock_cli.py /usr/local/bin/entrypoint.sh
EXPOSE 22
CMD ["/usr/local/bin/entrypoint.sh"]
