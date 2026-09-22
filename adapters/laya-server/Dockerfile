# laya-server: a fine-tuned Laya model behind the System One protocol.
#
#   docker build -t laya-server adapters/laya-server
#   docker run --rm -p 8080:8080 -v /path/to/finetuned:/model:ro \
#     -e LAYA_TEMPERATURE=1.7 -e LAYA_API_KEY=... laya-server
#
# /model holds model.onnx and tokenizer.json. The base Laya model is not
# usable for this task without fine-tuning (README.md).
# LAYA_BACKEND=mock runs without a model, for conformance runs and CI.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY laya_server.py fit_temperature.py ./

ENV LAYA_HOST=0.0.0.0 LAYA_PORT=8080 LAYA_MODEL_DIR=/model PYTHONUNBUFFERED=1
EXPOSE 8080
USER nobody
HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=1).status == 200 else 1)"
CMD ["python3", "laya_server.py"]
