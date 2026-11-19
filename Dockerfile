# CART — Continuous Automated Red Teaming
# OPTIONAL packaging. The project also runs with plain `python run.py`;
# deleting this file (and docker-compose.yml) changes nothing about that.
#
# Inside the container CART needs no GPU and no API keys. It starts the 6
# vulnerable lab targets itself (on localhost inside the container) and runs
# the full scan.

FROM python:3.12-slim

# keep Python output unbuffered and skip .pyc files
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy the project
COPY . .

# the scan writes its HTML/JSON report here; mount it to read results on the host
VOLUME ["/app/reports"]

# dashboard port (only used by the optional "dashboard" compose service)
EXPOSE 8501

# default: run the whole scan (no GPU needed)
CMD ["python", "run.py"]
