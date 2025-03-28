package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeRushOJ/sandbox/pkg/config"
	"github.com/CodeRushOJ/sandbox/pkg/models"
)

// Executor 代码执行器接口
type Executor interface {
	// Compile 编译代码
	Compile(ctx context.Context, code string, workDir string) (*models.CompileResult, error)
	
	// Run 运行代码
	Run(ctx context.Context, input string, workDir string, timeLimit, memoryLimit int) (*models.RunResult, error)
}

// LanguageExecutor 针对特定语言的执行器
type LanguageExecutor struct {
	language       models.Language
	langConfig     config.LangSpecificConfig
	securityConfig config.SecurityConfig
}

// NewExecutor 创建语言执行器
func NewExecutor(language models.Language, langConfig config.LangSpecificConfig, securityConfig config.SecurityConfig) Executor {
	return &LanguageExecutor{
		language:       language,
		langConfig:     langConfig,
		securityConfig: securityConfig,
	}
}

// Compile 编译代码
func (e *LanguageExecutor) Compile(ctx context.Context, code string, workDir string) (*models.CompileResult, error) {
	// 对于不需要编译的语言（如Python），直接返回成功
	if len(e.langConfig.CompileCommand) == 0 {
		return &models.CompileResult{
			Success:     true,
			ErrorOutput: "",
		}, nil
	}
	
	// 创建源代码文件
	sourceFilePath := filepath.Join(workDir, e.langConfig.FileName)
	if err := os.WriteFile(sourceFilePath, []byte(code), 0644); err != nil {
		return nil, fmt.Errorf("failed to write source file: %v", err)
	}
	
	// 创建编译命令
	cmd := exec.CommandContext(ctx, e.langConfig.CompileCommand[0], e.langConfig.CompileCommand[1:]...)
	cmd.Dir = workDir
	
	// 捕获标准错误
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	// 运行编译命令
	err := cmd.Run()
	
	// 处理编译结果
	if err != nil {
		return &models.CompileResult{
			Success:     false,
			ErrorOutput: stderr.String(),
		}, nil
	}
	
	return &models.CompileResult{
		Success:     true,
		ErrorOutput: stderr.String(),
	}, nil
}

// Run 运行代码
func (e *LanguageExecutor) Run(ctx context.Context, input string, workDir string, timeLimit, memoryLimit int) (*models.RunResult, error) {
	// 创建输入文件
	inputFilePath := filepath.Join(workDir, "input.txt")
	if err := os.WriteFile(inputFilePath, []byte(input), 0644); err != nil {
		return nil, fmt.Errorf("failed to write input file: %v", err)
	}
	
	// 创建运行命令
	cmd := exec.CommandContext(ctx, e.langConfig.RunCommand[0], e.langConfig.RunCommand[1:]...)
	cmd.Dir = workDir
	
	// 捕获标准输入、输出和错误
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()
	
	cmd.Stdin = inputFile
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	// 设置执行环境
	cmd.Env = os.Environ()
	
	// 应用安全限制（仅在Linux系统上有效）
	if err := applySecurityLimits(cmd, e.securityConfig, memoryLimit); err != nil {
		return nil, fmt.Errorf("failed to apply security limits: %v", err)
	}
	
	// 记录执行开始时间
	startTime := time.Now()
	
	// 运行命令
	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start command: %v", err)
	}
	
	// 创建一个计时器，用于强制终止超时的进程
	var timedOut bool
	timer := time.AfterFunc(time.Duration(timeLimit)*time.Millisecond, func() {
		timedOut = true
		cmd.Process.Kill()
	})
	defer timer.Stop()
	
	// 等待命令执行完成
	err = cmd.Wait()
	
	// 计算执行时间
	executionTime := time.Since(startTime)
	timeUsed := int(executionTime.Milliseconds())
	
	// 处理运行结果
	var exitCode int
	var status models.ExecutionStatus
	
	if timedOut {
		status = models.TimeLimited
		exitCode = -1
	} else if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			status = models.RuntimeErr
		} else {
			return nil, fmt.Errorf("failed to execute command: %v", err)
		}
	} else {
		exitCode = 0
		status = models.Accepted
	}
	
	// 创建结果
	result := &models.RunResult{
		Status:      status,
		Output:      stdout.String(),
		ErrorOutput: stderr.String(),
		ExitCode:    exitCode,
		TimeUsed:    timeUsed,
		MemoryUsed:  estimateMemoryUsage(workDir), // 简化实现，实际应使用cgroups或类似技术
	}
	
	return result, nil
}

// 应用安全限制
func applySecurityLimits(cmd *exec.Cmd, secConfig config.SecurityConfig, memoryLimit int) error {
	// 注意：这是一个简化的实现，真实实现应该使用Linux的seccomp、cgroups等
	
	// 在Linux系统上可以使用ulimit或setrlimit设置进程级别的资源限制
	// 在这个简化版本中，我们只是在环境变量中添加设置
	
	// 限制内存使用
	cmd.Env = append(cmd.Env, fmt.Sprintf("MEMORY_LIMIT=%d", memoryLimit))
	
	// 限制进程数
	cmd.Env = append(cmd.Env, fmt.Sprintf("MAX_PROCESSES=%d", secConfig.MaxProcesses))
	
	return nil
}

// 估计内存使用（简化实现）
func estimateMemoryUsage(workDir string) int {
	// 在实际实现中，应该使用cgroups或类似技术来获取精确的内存使用情况
	// 这里只是一个简化的实现，通过工作目录大小粗略估计
	var totalSize int64 = 0
	
	// 计算工作目录大小
	err := filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	
	if err != nil {
		return 0
	}
	
	// 转换为KB并返回一个保守的估计
	return int(totalSize/1024) + 1000
}

// FormatExecutionCommand 格式化执行命令
func FormatExecutionCommand(cmd []string) string {
	return strings.Join(cmd, " ")
}

// GetLanguageExecutor 获取特定语言的执行器
func GetLanguageExecutor(language models.Language, config *config.SandboxConfig) (Executor, error) {
	var langConfig config.LangSpecificConfig
	
	switch language {
	case models.Go:
		langConfig = config.Language.Go
	case models.Cpp:
		langConfig = config.Language.Cpp
	case models.Java:
		langConfig = config.Language.Java
	case models.Python:
		langConfig = config.Language.Python
	default:
		return nil, fmt.Errorf("unsupported language: %s", language)
	}
	
	return NewExecutor(language, langConfig, config.Security), nil
}

// DetectInfiniteLoop 检测无限循环
func DetectInfiniteLoop(output string) bool {
	// 简单实现：检查输出是否超过某个阈值
	return len(output) > 1000000
}

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	
	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()
	
	_, err = io.Copy(destFile, sourceFile)
	return err
}