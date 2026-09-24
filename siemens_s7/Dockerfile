FROM python:3.9-slim

# Desactivar el buffer de salida de Python para Docker
ENV PYTHONUNBUFFERED=1

# Instala libsnap7 para poder usar S7 y se eliminan las listas apt
RUN apt-get update && apt-get install -y libsnap7-dev && rm -rf /var/lib/apt/lists/*
RUN pip install python-snap7

COPY simulador_s7.py /simulador_s7.py

EXPOSE 102

CMD ["python", "/simulador_s7.py"]