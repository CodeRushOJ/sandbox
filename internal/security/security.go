package security

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeRushOJ/sandbox/pkg/config"
	"github.com/CodeRushOJ/sandbox/pkg/models"
)

// Security 安全管理器
type Security struct {
	config *config.SecurityConfig
}

// NewSecurity 创建安全管理器
func NewSecurity(config *config.SecurityConfig) *Security {
	return &Security{
		config: config,
	}
}

// CheckCode 检查代码安全性
func (s *Security) CheckCode(code string, language models.Language) error {
	// 根据语言选择不同的安全检查
	switch language {
	case models.Go:
		return s.checkGoCode(code)
	case models.Cpp:
		return s.checkCppCode(code)
	case models.Java:
		return s.checkJavaCode(code)
	case models.Python:
		return s.checkPythonCode(code)
	default:
		return fmt.Errorf("unsupported language for security check: %s", language)
	}
}

// CheckWorkingDir 检查工作目录大小
func (s *Security) CheckWorkingDir(workDir string) error {
	var size int64 = 0
	err := filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		// 如果大小超过限制，立即返回错误
		if size > s.config.WorkingDirSize*1024*1024 {
			return fmt.Errorf("working directory size exceeded limit")
		}
		return nil
	})
	
	return err
}

// checkGoCode 检查Go代码安全性
func (s *Security) checkGoCode(code string) error {
	// 检查危险导入
	dangerousImports := []string{
		"os/exec",
		"syscall",
		"unsafe",
		"net",
		"net/http",
	}
	
	for _, imp := range dangerousImports {
		if regexp.MustCompile(`import\s+["']` + imp + `["']`).MatchString(code) ||
		   regexp.MustCompile(`import\s+\(.*["']` + imp + `["'].*\)`).MatchString(code) {
			return fmt.Errorf("forbidden import: %s", imp)
		}
	}
	
	// 检查文件操作
	if s.config.DisableFileWrite {
		fileOps := []string{
			"os\\.Create",
			"os\\.OpenFile",
			"os\\.MkdirAll",
			"os\\.Mkdir",
			"ioutil\\.WriteFile",
			"io/ioutil\\.WriteFile",
		}
		
		for _, op := range fileOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden file operation: %s", op)
			}
		}
	}
	
	// 检查网络操作
	if s.config.DisableNetwork {
		networkOps := []string{
			"net\\.Dial",
			"net\\.Listen",
			"http\\.Get",
			"http\\.Post",
		}
		
		for _, op := range networkOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden network operation: %s", op)
			}
		}
	}
	
	// 检查进程操作
	if s.config.DisableFork {
		processOps := []string{
			"exec\\.Command",
			"syscall\\.ForkExec",
			"syscall\\.StartProcess",
		}
		
		for _, op := range processOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden process operation: %s", op)
			}
		}
	}
	
	return nil
}

// checkCppCode 检查C++代码安全性
func (s *Security) checkCppCode(code string) error {
	// 检查危险头文件
	dangerousHeaders := []string{
		"<sys/socket.h>",
		"<unistd.h>",
		"<sys/types.h>",
		"<sys/stat.h>",
		"<sys/ptrace.h>",
		"<fcntl.h>",
		"<netinet/in.h>",
		"<arpa/inet.h>",
	}
	
	for _, header := range dangerousHeaders {
		if strings.Contains(code, "#include "+header) {
			return fmt.Errorf("forbidden header: %s", header)
		}
	}
	
	// 检查系统调用
	if s.config.DisableFork {
		systemCalls := []string{
			"fork\\(", 
			"exec",
			"system\\(",
			"popen\\(",
		}
		
		for _, syscall := range systemCalls {
			if regexp.MustCompile(syscall).MatchString(code) {
				return fmt.Errorf("forbidden system call: %s", syscall)
			}
		}
	}
	
	// 检查文件操作
	if s.config.DisableFileWrite {
		fileOps := []string{
			"fopen\\(",
			"open\\(",
			"ofstream",
			"std::ofstream",
		}
		
		for _, op := range fileOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden file operation: %s", op)
			}
		}
	}
	
	// 检查网络操作
	if s.config.DisableNetwork {
		networkOps := []string{
			"socket\\(",
			"connect\\(",
			"bind\\(",
			"listen\\(",
		}
		
		for _, op := range networkOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden network operation: %s", op)
			}
		}
	}
	
	return nil
}

// checkJavaCode 检查Java代码安全性
func (s *Security) checkJavaCode(code string) error {
	// 检查危险导入
	dangerousImports := []string{
		"java.io.File",
		"java.net.Socket",
		"java.net.ServerSocket",
		"java.lang.ProcessBuilder",
		"java.lang.Runtime",
		"javax.script",
	}
	
	for _, imp := range dangerousImports {
		if regexp.MustCompile(`import\s+` + strings.Replace(imp, ".", "\\.", -1)).MatchString(code) {
			return fmt.Errorf("forbidden import: %s", imp)
		}
	}
	
	// 检查文件操作
	if s.config.DisableFileWrite {
		fileOps := []string{
			"new\\s+File\\(",
			"FileWriter",
			"FileOutputStream",
		}
		
		for _, op := range fileOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden file operation: %s", op)
			}
		}
	}
	
	// 检查网络操作
	if s.config.DisableNetwork {
		networkOps := []string{
			"new\\s+Socket\\(",
			"new\\s+ServerSocket\\(",
			"new\\s+URL\\(",
		}
		
		for _, op := range networkOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden network operation: %s", op)
			}
		}
	}
	
	// 检查进程操作
	if s.config.DisableFork {
		processOps := []string{
			"Runtime\\.getRuntime\\(\\)\\.exec\\(",
			"new\\s+ProcessBuilder\\(",
		}
		
		for _, op := range processOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden process operation: %s", op)
			}
		}
	}
	
	// 检查反射和SecurityManager操作
	restrictedOps := []string{
		"System\\.setSecurityManager\\(",
		"Class\\.forName\\(",
	}
	
	for _, op := range restrictedOps {
		if regexp.MustCompile(op).MatchString(code) {
			return fmt.Errorf("forbidden operation: %s", op)
		}
	}
	
	return nil
}

// checkPythonCode 检查Python代码安全性
func (s *Security) checkPythonCode(code string) error {
	// 检查危险导入
	dangerousImports := []string{
		"os",
		"subprocess",
		"sys",
		"socket",
		"pty",
		"shutil",
		"tempfile",
		"multiprocessing",
	}
	
	for _, imp := range dangerousImports {
		if regexp.MustCompile(`import\s+` + imp).MatchString(code) ||
		   regexp.MustCompile(`from\s+` + imp + `\s+import`).MatchString(code) {
			return fmt.Errorf("forbidden import: %s", imp)
		}
	}
	
	// 检查文件操作
	if s.config.DisableFileWrite {
		fileOps := []string{
			"open\\(.+,\\s*['\"]w['\"]",
			"open\\(.+,\\s*['\"]a['\"]",
			"write\\(",
		}
		
		for _, op := range fileOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden file operation: %s", op)
			}
		}
	}
	
	// 检查网络操作
	if s.config.DisableNetwork {
		networkOps := []string{
			"socket\\.",
			"urllib",
			"requests\\.",
			"http\\.",
		}
		
		for _, op := range networkOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden network operation: %s", op)
			}
		}
	}
	
	// 检查进程操作
	if s.config.DisableFork {
		processOps := []string{
			"subprocess\\.",
			"os\\.system\\(",
			"os\\.spawn",
			"os\\.popen\\(",
			"exec\\(",
			"eval\\(",
		}
		
		for _, op := range processOps {
			if regexp.MustCompile(op).MatchString(code) {
				return fmt.Errorf("forbidden process operation: %s", op)
			}
		}
	}
	
	// 检查其他危险操作
	dangerousOps := []string{
		"__import__\\(",
		"globals\\(\\)",
		"locals\\(\\)",
		"getattr\\(",
		"setattr\\(",
	}
	
	for _, op := range dangerousOps {
		if regexp.MustCompile(op).MatchString(code) {
			return fmt.Errorf("forbidden dangerous operation: %s", op)
		}
	}
	
	return nil
}

// SanitizeOutput 清理输出
func SanitizeOutput(output string, maxLength int) string {
	// 截断过长的输出
	if len(output) > maxLength {
		return output[:maxLength] + "... (output truncated)"
	}
	
	// 清理控制字符
	r := regexp.MustCompile(`[\x00-\x09\x0B\x0C\x0E-\x1F\x7F]`)
	output = r.ReplaceAllString(output, "")
	
	return output
}

// SecureDelete 安全删除目录
func SecureDelete(path string) error {
	// 首先检查路径是否合法
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	
	// 简单的安全检查，确保不会误删重要目录
	unsafePaths := []string{
		"/",
		"/bin",
		"/boot",
		"/dev",
		"/etc",
		"/home",
		"/lib",
		"/lib64",
		"/proc",
		"/root",
		"/sbin",
		"/sys",
		"/tmp",
		"/usr",
		"/var",
	}
	
	for _, unsafePath := range unsafePaths {
		if absPath == unsafePath {
			return fmt.Errorf("attempting to delete protected directory: %s", absPath)
		}
	}
	
	// 逐个删除文件而不是使用os.RemoveAll
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// 后序遍历，先处理文件再处理目录
		if !info.IsDir() {
			return os.Remove(filePath)
		}
		return nil
	})
}