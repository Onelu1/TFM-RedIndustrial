# Imagen Suricata para el laboratorio TFM.
# jasonish/suricata es la referencia oficial recomendada por el proyecto OISF.
FROM jasonish/suricata:latest

# Monta reglas y config desde /datos/config (volumen).
VOLUME ["/datos/pcaps", "/datos/salida", "/etc/suricata/rules"]
WORKDIR /datos

# No arranca nada por defecto: el script evaluar.sh lanza suricata en modo
# offline (-r <pcap>) por cada captura etiquetada.
CMD ["suricata", "--help"]
