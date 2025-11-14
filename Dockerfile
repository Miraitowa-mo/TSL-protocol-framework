FROM registry.cn-hangzhou.aliyuncs.com/google_containers/python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 设置默认命令
CMD ["python", "--version"]
