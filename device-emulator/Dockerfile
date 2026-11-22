FROM python:3.12-alpine
RUN apk add --no-cache openssh-server && \
    ssh-keygen -A && \
    adduser -D -s /usr/local/bin/mock_cli.py audit && \
    echo "audit:audit123" | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY mock_cli.py /usr/local/bin/mock_cli.py
RUN chmod +x /usr/local/bin/mock_cli.py
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
