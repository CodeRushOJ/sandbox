package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/google/uuid"

	"github.com/CodeRushOJ/sandbox/internal/security"
	"github.com/CodeRushOJ/sandbox/pkg/config"
	"github.com/CodeRushOJ/sandbox/pkg/models"
)

// DockerSandbox 基于Docker的沙盒实现
type DockerSandbox struct {
	client      *client.Client
	config      *config.SandboxConfig
	security    *security.Security
	languageMap map[models.Language]*LanguageConfig
}

// LanguageConfig 语言配置
type LanguageConfig struct {
	Image          string
	Extension      string
	CompileCommand []string
	RunCommand     []string
}

// NewSandbox 创建Docker沙盒
func NewSandbox(cfg *config.SandboxConfig) (*DockerSandbox, error) {
	// 创建Docker客户端
	clientOptions := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	
	// 如果提供了DockerHost，使用它
	if cfg.Docker.DockerHost != "" {
		clientOptions = append(clientOptions, client.WithHost(cfg.Docker.DockerHost))
	}
	
	cli, err := client.NewClientWithOpts(clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}
	
	// 创建安全管理器
	securityManager := security.NewSecurity(&cfg.Security)
	
	// 创建语言配置映射
	languageMap := map[models.Language]*LanguageConfig{
		models.Go: {
			Image:          cfg.Language.Go.Image,
			Extension:      ".go",
			CompileCommand: cfg.Language.Go.CompileCommand,
			RunCommand:     cfg.Language.Go.RunCommand,
		},
		models.Cpp: {
			Image:          cfg.Language.Cpp.Image,
			Extension:      ".cpp",
			CompileCommand: cfg.Language.Cpp.CompileCommand,
			RunCommand:     cfg.Language.Cpp.RunCommand,
		},
		models.Java: {
			Image:          cfg.Language.Java.Image,
			Extension:      ".java",
			CompileCommand: cfg.Language.Java.CompileCommand,
			RunCommand:     cfg.Language.Java.RunCommand,
		},
		models.Python: {
			Image:          cfg.Language.Python.Image,
			Extension:      ".py",
			CompileCommand: cfg.Language.Python.CompileCommand,
			RunCommand:     cfg.Language.Python.RunCommand,
		},
	}
	
	return &DockerSandbox{
		client:      cli,
		config:      cfg,
		security:    securityManager,
		languageMap: languageMap,
	}, nil
}

// Execute 执行代码
func (s *DockerSandbox) Execute(req *models.ExecuteRequest) (*models.ExecuteResponse, error) {
	// 获取语言配置
	langConfig, ok := s.languageMap[req.Language]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %s", req.Language)
	}
	
	// 检查代码安全性
	if err := s.security.CheckCode(req.Code, req.Language); err != nil {
		return &models.ExecuteResponse{
			Status:      models.SecurityErr,
			Output:      "",
			ErrorOutput: err.Error(),
			TimeUsed:    0,
			MemoryUsed:  0,
			Message:     "Security check failed",
		}, nil
	}
	
	// 创建工作目录
	workID := uuid.New().String()
	workDir := filepath.Join(s.config.Docker.TempDir, workID)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}
	defer s.cleanupWorkDir(workDir)
	
	// 创建上下文
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(s.config.Docker.Timeout)*time.Second,
	)
	defer cancel()
	
	// 编译代码
	compileResult, err := s.compileCode(ctx, req.Code, langConfig, workDir)
	if err != nil {
		return nil, fmt.Errorf("compilation error: %w", err)
	}
	
	if !compileResult.Success {
		return &models.ExecuteResponse{
			Status:      models.CompileErr,
			Output:      "",
			ErrorOutput: compileResult.ErrorOutput,
			TimeUsed:    0,
			MemoryUsed:  0,
			Message:     "Compilation failed",
		}, nil
	}
	
	// 运行代码
	runResult, err := s.runCode(ctx, req.Input, langConfig, workDir, req.TimeLimit, req.MemoryLimit)
	if err != nil {
		return nil, fmt.Errorf("execution error: %w", err)
	}
	
	// 清理工作目录
	return &models.ExecuteResponse{
		Status:      runResult.Status,
		Output:      runResult.Output,
		ErrorOutput: runResult.ErrorOutput,
		TimeUsed:    runResult.TimeUsed,
		MemoryUsed:  runResult.MemoryUsed,
		Message:     s.getStatusMessage(runResult.Status),
	}, nil
}

// 编译代码
func (s *DockerSandbox) compileCode(
	ctx context.Context,
	code string,
	langConfig *LanguageConfig,
	workDir string,
) (*models.CompileResult, error) {
	// 跳过不需要编译的语言
	if len(langConfig.CompileCommand) == 0 {
		return &models.CompileResult{Success: true}, nil
	}
	
	// 准备源文件
	codeFileName := "main" + langConfig.Extension
	if langConfig.Extension == ".java" {
		codeFileName = "Main.java"
	}
	
	codePath := filepath.Join(workDir, codeFileName)
	if err := os.WriteFile(codePath, []byte(code), 0644); err != nil {
		return nil, fmt.Errorf("failed to write source file: %w", err)
	}
	
	// 创建编译容器
	containerConfig := &container.Config{
		Image:      langConfig.Image,
		Cmd:        langConfig.CompileCommand,
		WorkingDir: "/sandbox",
		Tty:        false,
	}
	
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: workDir,
				Target: "/sandbox",
			},
		},
		NetworkMode: container.NetworkMode(s.config.Docker.NetworkMode),
		Resources: container.Resources{
			Memory:     s.config.Docker.MaxMemory * 1024 * 1024,
			MemorySwap: s.config.Docker.MaxMemory * 1024 * 1024,
			CPUPeriod:  100000,
			CPUQuota:   int64(parseFloat(s.config.Docker.CPULimit) * 100000),
			PidsLimit:  &[]int64{int64(s.config.Security.MaxProcesses)}[0],
		},
		AutoRemove: true,
	}
	
	// 创建容器
	resp, err := s.client.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		nil,
		nil,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create compilation container: %w", err)
	}
	containerID := resp.ID
	
	// 确保容器被移除
	defer s.removeContainer(containerID)
	
	// 启动容器
	if err := s.client.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start compilation container: %w", err)
	}
	
	// 等待编译完成
	statusCh, errCh := s.client.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	var result models.CompileResult
	
	select {
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("error waiting for compilation container: %w", err)
		}
	case status := <-statusCh:
		// 检查编译是否成功
		success := status.StatusCode == 0
		
		// 如果编译失败，获取错误输出
		errorOutput := ""
		if !success {
			logs, err := s.client.ContainerLogs(
				ctx,
				containerID,
				types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true},
			)
			if err == nil {
				defer logs.Close()
				stderr, _ := io.ReadAll(logs)
				errorOutput = string(stderr)
				
				// 清理/限制输出大小
				errorOutput = security.SanitizeOutput(errorOutput, 10000)
			}
		}
		
		result = models.CompileResult{
			Success:     success,
			ErrorOutput: errorOutput,
		}
	}
	
	return &result, nil
}

// 运行代码
func (s *DockerSandbox) runCode(
	ctx context.Context,
	input string,
	langConfig *LanguageConfig,
	workDir string,
	timeLimit, memoryLimit int,
) (*models.RunResult, error) {
	// 写入输入文件
	inputPath := filepath.Join(workDir, "input.txt")
	if err := os.WriteFile(inputPath, []byte(input), 0644); err != nil {
		return nil, fmt.Errorf("failed to write input file: %w", err)
	}
	
	// 创建运行容器
	containerConfig := &container.Config{
		Image:      langConfig.Image,
		Cmd:        langConfig.RunCommand,
		WorkingDir: "/sandbox",
		Tty:        false,
		OpenStdin:  true,
		StdinOnce:  true,
	}
	
	// 设置内存限制 (KB -> bytes)
	memLimitBytes := int64(memoryLimit) * 1024
	if memLimitBytes > s.config.Docker.MaxMemory*1024*1024 {
		memLimitBytes = s.config.Docker.MaxMemory * 1024 * 1024
	}
	
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: workDir,
				Target: "/sandbox",
			},
		},
		NetworkMode: container.NetworkMode(s.config.Docker.NetworkMode),
		Resources: container.Resources{
			Memory:     memLimitBytes,
			MemorySwap: memLimitBytes,
			CPUPeriod:  100000,
			CPUQuota:   int64(parseFloat(s.config.Docker.CPULimit) * 100000),
			PidsLimit:  &[]int64{int64(s.config.Security.MaxProcesses)}[0],
		},
		AutoRemove: true,
		SecurityOpt: []string{"no-new-privileges"},
	}
	
	// 创建容器
	resp, err := s.client.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		nil,
		nil,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution container: %w", err)
	}
	containerID := resp.ID
	
	// 确保容器被移除
	defer s.removeContainer(containerID)
	
	// 为执行设置更严格的超时
	execCtx, execCancel := context.WithTimeout(
		ctx,
		time.Duration(timeLimit+1000)*time.Millisecond,
	)
	defer execCancel()
	
	// 启动容器
	startTime := time.Now()
	if err := s.client.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start execution container: %w", err)
	}
	
	// 如果有输入，连接到容器的标准输入
	if input != "" {
		attachOptions := types.ContainerAttachOptions{
			Stream: true,
			Stdin:  true,
			Stdout: false,
			Stderr: false,
		}
		
		hijackedResp, err := s.client.ContainerAttach(ctx, containerID, attachOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to attach to container: %w", err)
		}
		defer hijackedResp.Close()
		
		// 将输入写入容器
		if _, err := hijackedResp.Conn.Write([]byte(input)); err != nil {
			return nil, fmt.Errorf("failed to write to container stdin: %w", err)
		}
		hijackedResp.CloseWrite()
	}
	
	// 等待容器执行完成或超时
	statusCh, errCh := s.client.ContainerWait(execCtx, containerID, container.WaitConditionNotRunning)
	
	var exitCode int
	var status models.ExecutionStatus
	var isTimeout bool
	
	select {
	case <-execCtx.Done():
		if execCtx.Err() == context.DeadlineExceeded {
			isTimeout = true
			status = models.TimeLimited
			exitCode = -1
		}
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("error waiting for execution container: %w", err)
		}
	case waitResp := <-statusCh:
		exitCode = int(waitResp.StatusCode)
		if exitCode == 0 {
			status = models.Accepted
		} else if exitCode == 137 { // SIGKILL (通常是内存超限)
			status = models.MemLimited
		} else {
			status = models.RuntimeErr
		}
	}
	
	// 计算执行时间
	executionTime := time.Since(startTime)
	timeUsed := int(executionTime.Milliseconds())
	
	// 设置状态
	if timeUsed > timeLimit && !isTimeout {
		status = models.TimeLimited
	}
	
	// 读取容器日志
	logs, err := s.client.ContainerLogs(
		context.Background(),
		containerID,
		types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}
	defer logs.Close()
	
	// 分离stdout和stderr
	stdout, stderr, err := s.splitDockerLogs(logs)
	if err != nil {
		return nil, fmt.Errorf("failed to split docker logs: %w", err)
	}
	
	// 清理和限制输出大小
	stdoutStr := security.SanitizeOutput(string(stdout), 10000)
	stderrStr := security.SanitizeOutput(string(stderr), 10000)
	
	// 获取内存使用情况
	memoryUsed := 0
	stats, err := s.client.ContainerStats(context.Background(), containerID, false)
	if err == nil {
		defer stats.Body.Close()
		var statsJSON types.StatsJSON
		if err := json.NewDecoder(stats.Body).Decode(&statsJSON); err == nil {
			// 将字节转为KB
			memoryUsed = int(statsJSON.MemoryStats.Usage / 1024)
		}
	}
	
	// 如果未能获取内存使用情况，设置一个估计值
	if memoryUsed == 0 {
		memoryUsed = memoryLimit / 2
	}
	
	// 检查内存限制
	if memoryUsed > memoryLimit {
		status = models.MemLimited
	}
	
	return &models.RunResult{
		Status:      status,
		Output:      stdoutStr,
		ErrorOutput: stderrStr,
		ExitCode:    exitCode,
		TimeUsed:    timeUsed,
		MemoryUsed:  memoryUsed,
	}, nil
}

// 分离Docker日志中的stdout和stderr
func (s *DockerSandbox) splitDockerLogs(reader io.Reader) ([]byte, []byte, error) {
	var stdout, stderr []byte
	buf := make([]byte, 8192)
	
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, err
		}
		
		if n < 8 {
			continue
		}
		
		// Docker日志格式：前8字节是头部，第一个字节表示流类型(1=stdout, 2=stderr)
		for i := 0; i < n; {
			if i+8 > n {
				break
			}
			
			// 获取帧大小
			frameSize := int(buf[i+4]) | int(buf[i+5])<<8 | int(buf[i+6])<<16 | int(buf[i+7])<<24
			if i+8+frameSize > n {
				break
			}
			
			// 根据流类型添加内容
			frame := buf[i+8 : i+8+frameSize]
			if buf[i] == 1 {
				stdout = append(stdout, frame...)
			} else if buf[i] == 2 {
				stderr = append(stderr, frame...)
			}
			
			i += 8 + frameSize
		}
	}
	
	return stdout, stderr, nil
}

// 清理工作目录
func (s *DockerSandbox) cleanupWorkDir(workDir string) {
	if err := security.SecureDelete(workDir); err != nil {
		fmt.Printf("Warning: Failed to clean up work directory: %v\n", err)
	}
}

// 移除容器
func (s *DockerSandbox) removeContainer(containerID string) {
	removeOptions := types.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	}
	
	if err := s.client.ContainerRemove(context.Background(), containerID, removeOptions); err != nil {
		fmt.Printf("Warning: Failed to remove container: %v\n", err)
	}
}

// 获取状态描述
func (s *DockerSandbox) getStatusMessage(status models.ExecutionStatus) string {
	switch status {
	case models.Accepted:
		return "Success"
	case models.WrongAnswer:
		return "Wrong Answer"
	case models.TimeLimited:
		return "Time Limit Exceeded"
	case models.MemLimited:
		return "Memory Limit Exceeded"
	case models.RuntimeErr:
		return "Runtime Error"
	case models.CompileErr:
		return "Compilation Error"
	case models.SecurityErr:
		return "Security Error"
	case models.PresentationErr:
		return "Presentation Error"
	case models.SystemErr:
		return "System Error"
	default:
		return "Unknown Status"
	}
}

// Cleanup 清理沙盒资源
func (s *DockerSandbox) Cleanup() error {
	return s.client.Close()
}

// 解析CPU限制
func parseFloat(value string) float64 {
	result, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0.5 // 默认值
	}
	return result
}