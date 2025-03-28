package models

// Language 定义支持的编程语言
type Language string

// 支持的编程语言枚举
const (
	Go     Language = "go"
	Cpp    Language = "cpp"
	Java   Language = "java"
	Python Language = "python"
)

// ExecutionStatus 表示代码执行状态
type ExecutionStatus string

// 执行状态枚举
const (
	Accepted         ExecutionStatus = "accepted"
	WrongAnswer      ExecutionStatus = "wrong_answer"
	TimeLimited      ExecutionStatus = "time_limit_exceeded"
	MemLimited       ExecutionStatus = "memory_limit_exceeded"
	RuntimeErr       ExecutionStatus = "runtime_error"
	CompileErr       ExecutionStatus = "compile_error"
	SystemErr        ExecutionStatus = "system_error"
	PresentationErr  ExecutionStatus = "presentation_error"
	SecurityErr      ExecutionStatus = "security_error"
)

// ExecuteRequest 表示执行代码的请求
type ExecuteRequest struct {
	Code        string   `json:"code"`
	Language    Language `json:"language"`
	Input       string   `json:"input"`
	TimeLimit   int      `json:"time_limit"`   // 毫秒
	MemoryLimit int      `json:"memory_limit"` // KB
}

// ExecuteResponse 表示执行代码的响应
type ExecuteResponse struct {
	Status      ExecutionStatus `json:"status"`
	Output      string          `json:"output"`
	ErrorOutput string          `json:"error_output"`
	TimeUsed    int             `json:"time_used"`    // 毫秒
	MemoryUsed  int             `json:"memory_used"`  // KB
	Message     string          `json:"message"`
}

// CompileResult 表示编译结果
type CompileResult struct {
	Success     bool   `json:"success"`
	ErrorOutput string `json:"error_output"`
}

// RunResult 表示运行结果
type RunResult struct {
	Status      ExecutionStatus `json:"status"`
	Output      string          `json:"output"`
	ErrorOutput string          `json:"error_output"`
	ExitCode    int             `json:"exit_code"`
	TimeUsed    int             `json:"time_used"`    // 毫秒
	MemoryUsed  int             `json:"memory_used"`  // KB
}

// Sandbox 沙盒接口定义
type Sandbox interface {
	// Execute 在沙盒环境中执行代码
	Execute(req *ExecuteRequest) (*ExecuteResponse, error)
	
	// Cleanup 清理沙盒资源
	Cleanup() error
}