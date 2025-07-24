FROM mitmproxy/mitmproxy:latest

# Копируем скрипт фильтрации и конфиг
COPY mitmproxy_scripts/whitelist_filter.py /scripts/whitelist_filter.py
COPY mitmproxy_scripts/whitelist_config.json /scripts/whitelist_config.json

# Копируем сертификаты во внутреннюю папку mitmproxy (будут использоваться для SSL MITM)
COPY mitmproxy_certs /home/mitmproxy/.mitmproxy

# Создаем папку для логов (если хотите писать в неё из скрипта)
RUN mkdir -p /logs

# Запускаем mitmweb с нужными параметрами
CMD ["mitmweb", \
    "--set", "confdir=/home/mitmproxy/.mitmproxy", \
    "--set", "web_host=0.0.0.0", \
    "--set", "web_port=8081", \
    "--set", "web_password=6ibdVQEunvGZcDcUR5gW", \
    "--no-web-open-browser", \
    "--scripts", "/scripts/whitelist_filter.py"]
