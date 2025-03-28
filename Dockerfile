# 构建阶段
FROM golang:1.19-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的工具
RUN apk add --no-cache git ca-certificates tzdata

# 复制Go模块定义
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o sandbox-server ./sandbox/cmd/sandbox

# 运行阶段
FROM alpine:3.16

# 安装Docker客户端
RUN apk add --no-cache docker-cli ca-certificates tzdata

# 创建非root用户
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# 设置工作目录
WORKDIR /app

# 从构建阶段复制可执行文件
COPY --from=builder /app/sandbox-server /app/

# 创建必要的目录
RUN mkdir -p /app/data /tmp/judge && \
    chown -R appuser:appgroup /app /tmp/judge

# 创建默认配置文件
COPY --from=builder /app/sandbox/sandbox-config.yaml /app/

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 8090

# 设置时区
ENV TZ=Asia/Shanghai

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8090/api/v1/health || exit 1

# 启动应用
ENTRYPOINT ["/app/sandbox-server"]