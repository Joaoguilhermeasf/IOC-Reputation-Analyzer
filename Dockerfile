# Usa imagem oficial do Python
FROM python:3.11-slim

# Define diretório de trabalho
WORKDIR /app

# Copia arquivos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Variável de ambiente (vai vir do .env ou docker run)
ENV PYTHONUNBUFFERED=1

# Comando padrão
CMD ["python", "main.py"]