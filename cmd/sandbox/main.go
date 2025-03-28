package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"github.com/CodeRushOJ/sandbox/internal/docker"
	"github.com/CodeRushOJ/sandbox/pkg/config"
	"github.com/CodeRushOJ/sandbox/pkg/models"
)

// App 应用结构
type App struct {
	config  *config.SandboxConfig
	sandbox models.Sandbox
	server  *http.Server
	router  *mux.Router
	
	// 限制并发请求
	semaphore chan struct{}
	
	// 状态监控
	mutex          sync.RWMutex
	requestCount   int64
	runningTasks   int
	failedRequests int64
}

// NewApp 创建应用
func NewApp() (*App, error) {
	// 加载配置
	cfg, err := config.Load(config.GetConfigFilePath())
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	
	// 创建沙盒
	sandbox, err := docker.NewSandbox(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox: %w", err)
	}
	
	// 创建路由
	router := mux.NewRouter()
	
	// 创建HTTP服务器
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// 创建应用
	app := &App{
		config:    cfg,
		sandbox:   sandbox,
		server:    server,
		router:    router,
		semaphore: make(chan struct{}, cfg.Server.MaxConcurrency),
	}
	
	// 设置路由
	app.setupRoutes()
	
	return app, nil
}

// 设置路由
func (a *App) setupRoutes() {
	// API版本前缀
	api := a.router.PathPrefix("/api/v1").Subrouter()
	
	// 健康检查
	api.HandleFunc("/health", a.healthCheckHandler).Methods("GET")
	
	// 执行代码
	api.HandleFunc("/execute", a.executeHandler).Methods("POST")
	
	// 状态监控
	api.HandleFunc("/status", a.statusHandler).Methods("GET")
	
	// 中间件
	api.Use(a.loggingMiddleware)
}

// 启动服务器
func (a *App) Start() error {
	// 启动HTTP服务器
	go func() {
		log.Printf("Starting sandbox server on %s", a.server.Addr)
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	
	// 捕获信号
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	
	// 等待信号
	<-stop
	log.Println("Shutting down server...")
	
	// 创建关闭超时上下文
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(a.config.Server.ShutdownTimeout)*time.Second,
	)
	defer cancel()
	
	// 优雅关闭
	if err := a.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}
	
	// 清理沙盒资源
	if err := a.sandbox.Cleanup(); err != nil {
		return fmt.Errorf("sandbox cleanup error: %w", err)
	}
	
	log.Println("Server stopped")
	return nil
}

// 健康检查处理器
func (a *App) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	a.mutex.RLock()
	status := "OK"
	if a.runningTasks >= a.config.Server.MaxConcurrency {
		status = "BUSY"
	}
	a.mutex.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         status,
		"version":        "1.0.0",
		"request_count":  a.requestCount,
		"running_tasks":  a.runningTasks,
		"failed_requests": a.failedRequests,
	})
}

// 状态处理器
func (a *App) statusHandler(w http.ResponseWriter, r *http.Request) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"request_count":   a.requestCount,
		"running_tasks":   a.runningTasks,
		"failed_requests": a.failedRequests,
		"max_concurrency": a.config.Server.MaxConcurrency,
		"available_slots": a.config.Server.MaxConcurrency - a.runningTasks,
		"languages": []string{
			string(models.Go),
			string(models.Cpp),
			string(models.Java),
			string(models.Python),
		},
	})
}

// 执行代码处理器
func (a *App) executeHandler(w http.ResponseWriter, r *http.Request) {
	// 解析请求
	var req models.ExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// 验证必要字段
	if req.Code == "" || req.Language == "" {
		a.respondWithError(w, http.StatusBadRequest, "Code and language are required")
		return
	}
	
	// 设置默认值
	if req.TimeLimit <= 0 {
		req.TimeLimit = 1000 // 默认1秒
	} else if req.TimeLimit > 10000 {
		req.TimeLimit = 10000 // 最大10秒
	}
	
	if req.MemoryLimit <= 0 {
		req.MemoryLimit = 262144 // 默认256MB
	} else if req.MemoryLimit > 1048576 {
		req.MemoryLimit = 1048576 // 最大1GB
	}
	
	// 获取信号量，限制并发执行
	select {
	case a.semaphore <- struct{}{}:
		// 继续执行
	default:
		// 达到最大并发数
		a.respondWithError(w, http.StatusTooManyRequests, "Server is at maximum capacity")
		return
	}
	
	// 更新计数器
	a.mutex.Lock()
	a.requestCount++
	a.runningTasks++
	a.mutex.Unlock()
	
	// 完成后释放信号量
	defer func() {
		<-a.semaphore
		a.mutex.Lock()
		a.runningTasks--
		a.mutex.Unlock()
	}()
	
	// 执行代码
	resp, err := a.sandbox.Execute(&req)
	if err != nil {
		log.Printf("Error executing code: %v", err)
		a.mutex.Lock()
		a.failedRequests++
		a.mutex.Unlock()
		a.respondWithError(w, http.StatusInternalServerError, "Failed to execute code")
		return
	}
	
	// 返回结果
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// 日志中间件
func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// 调用下一个处理器
		next.ServeHTTP(w, r)
		
		// 记录请求信息
		log.Printf(
			"%s %s %s %s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			time.Since(start),
		)
	})
}

// 返回错误响应
func (a *App) respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func main() {
	// 创建应用
	app, err := NewApp()
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	
	// 启动服务器
	if err := app.Start(); err != nil {
		log.Fatalf("Error running server: %v", err)
	}
}