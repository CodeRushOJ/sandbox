package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// SandboxConfig 表示沙盒配置
type SandboxConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Docker   DockerConfig   `yaml:"docker"`
	Security SecurityConfig `yaml:"security"`
	Language LanguageConfig `yaml:"language"`
	Storage  StorageConfig  `yaml:"storage"`
}

// ServerConfig 表示服务器配置
type ServerConfig struct {
	Port            int    `yaml:"port"`
	Host            string `yaml:"host"`
	MaxConcurrency  int    `yaml:"max_concurrency"`
	ShutdownTimeout int    `yaml:"shutdown_timeout"` // 秒
}

// DockerConfig 表示Docker配置
type DockerConfig struct {
	NetworkMode  string `yaml:"network_mode"`  // none, host, bridge
	DisableCache bool   `yaml:"disable_cache"` // 是否禁用缓存
	Timeout      int    `yaml:"timeout"`       // 秒
	TempDir      string `yaml:"temp_dir"`
	MaxMemory    int64  `yaml:"max_memory"`    // MB
	CPULimit     string `yaml:"cpu_limit"`     // CPU限制 (如 "0.5")
	DockerHost   string `yaml:"docker_host"`   // Docker守护进程地址
}

// SecurityConfig 表示安全配置
type SecurityConfig struct {
	DisableFork      bool     `yaml:"disable_fork"`
	DisableNetwork   bool     `yaml:"disable_network"`
	DisableFileWrite bool     `yaml:"disable_file_write"`
	MaxProcesses     int      `yaml:"max_processes"`
	BlockedSyscalls  []string `yaml:"blocked_syscalls"`
	WorkingDirSize   int64    `yaml:"working_dir_size"` // MB
}

// LanguageConfig 表示语言配置
type LanguageConfig struct {
	Go     LangSpecificConfig `yaml:"go"`
	Cpp    LangSpecificConfig `yaml:"cpp"`
	Java   LangSpecificConfig `yaml:"java"`
	Python LangSpecificConfig `yaml:"python"`
}

// LangSpecificConfig 表示特定语言的配置
type LangSpecificConfig struct {
	Image          string   `yaml:"image"`
	Version        string   `yaml:"version"`
	CompileCommand []string `yaml:"compile_command"`
	RunCommand     []string `yaml:"run_command"`
	FileName       string   `yaml:"file_name"`
	Timeout        int      `yaml:"timeout"` // 秒
}

// StorageConfig 表示存储配置
type StorageConfig struct {
	Type string `yaml:"type"` // file, memory, etc.
	Path string `yaml:"path"` // 文件存储路径
}

// DefaultConfig 返回默认配置
func DefaultConfig() *SandboxConfig {
	return &SandboxConfig{
		Server: ServerConfig{
			Port:            8090,
			Host:            "0.0.0.0",
			MaxConcurrency:  10,
			ShutdownTimeout: 30,
		},
		Docker: DockerConfig{
			NetworkMode:  "none",
			DisableCache: true,
			Timeout:      10,
			TempDir:      "/tmp/judge",
			MaxMemory:    256,  // 256MB
			CPULimit:     "0.5", // 0.5 CPU
			DockerHost:   "",   // 默认
		},
		Security: SecurityConfig{
			DisableFork:      true,
			DisableNetwork:   true,
			DisableFileWrite: true,
			MaxProcesses:     50,
			BlockedSyscalls:  []string{"socket", "clone", "fork", "vfork", "execve", "kill"},
			WorkingDirSize:   50, // 50MB
		},
		Language: LanguageConfig{
			Go: LangSpecificConfig{
				Image:          "golang:1.19-alpine",
				Version:        "1.19",
				CompileCommand: []string{"go", "build", "-o", "app"},
				RunCommand:     []string{"./app"},
				FileName:       "main.go",
				Timeout:        5,
			},
			Cpp: LangSpecificConfig{
				Image:          "gcc:11-alpine",
				Version:        "11",
				CompileCommand: []string{"g++", "-std=c++17", "-O2", "-o", "app", "main.cpp"},
				RunCommand:     []string{"./app"},
				FileName:       "main.cpp",
				Timeout:        5,
			},
			Java: LangSpecificConfig{
				Image:          "openjdk:17-alpine",
				Version:        "17",
				CompileCommand: []string{"javac", "Main.java"},
				RunCommand:     []string{"java", "Main"},
				FileName:       "Main.java",
				Timeout:        10,
			},
			Python: LangSpecificConfig{
				Image:          "python:3.9-alpine",
				Version:        "3.9",
				CompileCommand: []string{},
				RunCommand:     []string{"python", "main.py"},
				FileName:       "main.py",
				Timeout:        5,
			},
		},
		Storage: StorageConfig{
			Type: "file",
			Path: "./data",
		},
	}
}

// Load 从文件加载配置
func Load(configPath string) (*SandboxConfig, error) {
	config := DefaultConfig()

	// 如果提供了配置文件，从文件加载
	if configPath != "" {
		configFile, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}

		if err := yaml.Unmarshal(configFile, config); err != nil {
			return nil, fmt.Errorf("error unmarshaling config: %w", err)
		}
	}

	// 从环境变量覆盖配置
	overrideFromEnv(config)

	// 确保必要的目录存在
	ensureDirectories(config)

	return config, nil
}

// 从环境变量覆盖配置
func overrideFromEnv(config *SandboxConfig) {
	// 服务器配置
	if port, err := strconv.Atoi(os.Getenv("SANDBOX_PORT")); err == nil && port > 0 {
		config.Server.Port = port
	}
	if host := os.Getenv("SANDBOX_HOST"); host != "" {
		config.Server.Host = host
	}
	if concurrency, err := strconv.Atoi(os.Getenv("SANDBOX_MAX_CONCURRENCY")); err == nil && concurrency > 0 {
		config.Server.MaxConcurrency = concurrency
	}

	// Docker配置
	if networkMode := os.Getenv("DOCKER_NETWORK_MODE"); networkMode != "" {
		config.Docker.NetworkMode = networkMode
	}
	if disableCache := os.Getenv("DOCKER_DISABLE_CACHE"); disableCache == "true" {
		config.Docker.DisableCache = true
	} else if disableCache == "false" {
		config.Docker.DisableCache = false
	}
	if timeout, err := strconv.Atoi(os.Getenv("DOCKER_TIMEOUT")); err == nil && timeout > 0 {
		config.Docker.Timeout = timeout
	}
	if tempDir := os.Getenv("DOCKER_TEMP_DIR"); tempDir != "" {
		config.Docker.TempDir = tempDir
	}
	if maxMemory, err := strconv.ParseInt(os.Getenv("DOCKER_MAX_MEMORY"), 10, 64); err == nil && maxMemory > 0 {
		config.Docker.MaxMemory = maxMemory
	}
	if cpuLimit := os.Getenv("DOCKER_CPU_LIMIT"); cpuLimit != "" {
		config.Docker.CPULimit = cpuLimit
	}
	if dockerHost := os.Getenv("DOCKER_HOST"); dockerHost != "" {
		config.Docker.DockerHost = dockerHost
	}

	// 安全配置
	if disableFork := os.Getenv("SECURITY_DISABLE_FORK"); disableFork == "true" {
		config.Security.DisableFork = true
	} else if disableFork == "false" {
		config.Security.DisableFork = false
	}
	if disableNetwork := os.Getenv("SECURITY_DISABLE_NETWORK"); disableNetwork == "true" {
		config.Security.DisableNetwork = true
	} else if disableNetwork == "false" {
		config.Security.DisableNetwork = false
	}
	if maxProcesses, err := strconv.Atoi(os.Getenv("SECURITY_MAX_PROCESSES")); err == nil && maxProcesses > 0 {
		config.Security.MaxProcesses = maxProcesses
	}
}

// 确保必要的目录存在
func ensureDirectories(config *SandboxConfig) {
	// 确保临时目录存在
	if err := os.MkdirAll(config.Docker.TempDir, 0755); err != nil {
		fmt.Printf("Warning: Failed to create temp directory: %v\n", err)
	}

	// 确保存储目录存在
	if config.Storage.Type == "file" && config.Storage.Path != "" {
		if err := os.MkdirAll(config.Storage.Path, 0755); err != nil {
			fmt.Printf("Warning: Failed to create storage directory: %v\n", err)
		}
	}
}

// GetConfigFilePath 返回配置文件的路径
func GetConfigFilePath() string {
	// 首先检查环境变量
	if configPath := os.Getenv("SANDBOX_CONFIG_PATH"); configPath != "" {
		return configPath
	}

	// 然后检查当前目录
	if _, err := os.Stat("sandbox-config.yaml"); err == nil {
		return "sandbox-config.yaml"
	}

	// 最后检查默认位置
	homeDir, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(homeDir, ".coderushoj", "sandbox-config.yaml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}

	return ""
}