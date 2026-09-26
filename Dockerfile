FROM python:3.11-slim

WORKDIR /app

# 创建日志目录与事件快照目录（stdout/stderr 与事件原始日志写入此处）
RUN mkdir -p /app/logs /app/data/event_snapshots

# 安装依赖及 curl（供 healthcheck 使用）
RUN apt-get update && apt-get install -y curl procps && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码及数据文件
COPY app.py .
COPY collector.py .
COPY config_manager.py .
COPY database.py .
COPY geo_resolver.py .
COPY notifier.py .
COPY access_control.py .
COPY static/ static/
COPY templates/ templates/

EXPOSE 5000

# 利用 /healthz 接口判定容器健康状态
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:5000/healthz || exit 1

# 容器启动时直接运行应用
CMD ["python", "app.py"]
