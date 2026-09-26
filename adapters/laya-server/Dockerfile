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
# probes where the server listens: LAYA_PORT, and LAYA_HOST unless that is a
# wildcard (0.0.0.0 / :: / empty), which is probed on loopback
HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
  CMD python3 -c "import os,sys,urllib.request as u; h=os.environ.get('LAYA_HOST','0.0.0.0'); h={'':'127.0.0.1','0.0.0.0':'127.0.0.1','::':'::1'}.get(h,h); h='['+h+']' if ':' in h else h; sys.exit(0 if u.urlopen('http://%s:%s/healthz'%(h,os.environ.get('LAYA_PORT','8080')),timeout=1).status==200 else 1)"
CMD ["python3", "laya_server.py"]
