# VulnShop is intentionally vulnerable. Run it only on a machine you control, on loopback.
#
# The app refuses to bind anything but 127.0.0.1, so a published port (-p) cannot reach it.
# Use the host network instead (Linux):
#   docker build -t vulnshop .
#   docker run --rm --network host vulnshop
# Port 5050 (app) and 5051 (fake internal service) then listen on the host's loopback only.
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnshop ./vulnshop
COPY reset.py .
RUN useradd --system --no-create-home shop && mkdir data && chown shop data
USER shop

ENV HOST=127.0.0.1 PORT=5050 PYTHONUNBUFFERED=1
CMD ["python", "-m", "vulnshop"]
