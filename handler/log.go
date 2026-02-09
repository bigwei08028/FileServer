package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 日志配置
var (
	logFile     *os.File
	logMutex    sync.Mutex
	logFilePath string
)

// InitLog 初始化日志系统
func InitLog() {
	// 获取可执行文件所在目录
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	// 创建 data 目录
	logDir := filepath.Join(exeDir, "data")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("创建日志目录失败: %v", err)
		return
	}

	// 日志文件路径
	logFilePath = filepath.Join(logDir, "app.log")

	// 打开日志文件（追加模式，不存在则创建）
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("打开日志文件失败: %v", err)
		return
	}
	logFile = file

	// 同时输出到标准日志
	log.SetOutput(os.Stdout)
}

// CloseLog 关闭日志系统
func CloseLog() {
	if logFile != nil {
		logFile.Close()
	}
}

// LogOperation 记录操作日志
func LogOperation(username, operation, details string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		InitLog()
	}

	// 格式化日志
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("%s - %s - %s - %s\n", timestamp, username, operation, details)

	// 写入文件
	if logFile != nil {
		logFile.WriteString(logEntry)
	}

	// 同时输出到控制台
	fmt.Print(logEntry)
}

// FrontendLogRequest 前端日志请求结构
type FrontendLogRequest struct {
	Username   string `json:"username"`
	Operation  string `json:"operation"`
	Details    string `json:"details"`
}

// FrontendLog 前端日志处理（无需认证）
func FrontendLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	var req FrontendLogRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		req.Username = "匿名用户"
	}

	LogOperation(req.Username, req.Operation, req.Details)

	sendSuccess(w, nil)
}

// 日志操作类型常量
const (
	OpLogin      = "登录"
	OpLogout     = "退出"
	OpPageAccess = "页面访问"
	OpDownload   = "下载"
	OpRename     = "重命名"
	OpDelete     = "删除"
	OpShare      = "分享链接"
	OpUpload     = "上传"
	OpCreateDir  = "创建文件夹"
	OpAccess     = "访问目录"
)
