package handler

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var pageTitle = "FileServer - 内网文件服务"
var rootPath = ""

// JWT 配置
var jwtSecret = []byte("file-server-secret-key-2024")
var jwtExpiry = 24 * time.Hour

// 用户配置（默认 admin/admin）
var DefaultUsername = "admin"
var DefaultPassword = "admin"

// SetUserCredentials 设置用户凭据
func SetUserCredentials(username, password string) {
	if username != "" {
		DefaultUsername = username
	}
	if password != "" {
		DefaultPassword = password
	}
}

// Claims JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateToken 生成 JWT token
func GenerateToken(username string) (string, error) {
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateToken 验证 JWT token
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

// Login 登录处理
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	// 加载用户数据
	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败", http.StatusInternalServerError)
		return
	}

	usersMutex.RLock()
	user, exists := usersMap[req.Username]
	usersMutex.RUnlock()

	if !exists {
		sendError(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	// 检查用户是否被禁用
	if user.IsDisabled {
		sendError(w, "账户已被禁用", http.StatusUnauthorized)
		return
	}

	// 验证密码（使用 MD5）
	if user.PasswordMD5 == md5Hash(req.Password) {
		// 生成 token
		token, err := GenerateToken(req.Username)
		if err != nil {
			sendError(w, "生成令牌失败", http.StatusInternalServerError)
			return
		}

		// 记录登录日志
		clientIP := r.RemoteAddr
		LogOperation(req.Username, OpLogin, "登录成功 - IP: "+clientIP)

		sendSuccess(w, map[string]interface{}{
			"token":    token,
			"username": req.Username,
			"isAdmin":  req.Username == DefaultUsername,
		})
		return
	}

	// 记录失败的登录尝试
	LogOperation(req.Username, OpLogin, "登录失败 - 用户名或密码错误")

	sendError(w, "用户名或密码错误", http.StatusUnauthorized)
}

// VerifyToken 验证 token
func VerifyToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		sendError(w, "未授权", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := ValidateToken(tokenString)
	if err != nil {
		sendError(w, "令牌无效或已过期", http.StatusUnauthorized)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"username": claims.Username,
		"isAdmin":  claims.Username == DefaultUsername,
	})
}

// SetRootPath 设置文件根目录
func SetRootPath(path string) {
	if path != "" {
		rootPath = path
	}
}

// GetRootPath 获取文件根目录
func GetRootPath() string {
	if rootPath == "" {
		rootPath, _ = os.Getwd()
	}
	return rootPath
}

// GetRelativePath 获取相对路径
func GetRelativePath(absPath string) string {
	absRootPath, _ := filepath.Abs(GetRootPath())
	relPath, _ := filepath.Rel(absRootPath, absPath)
	return relPath
}

// GetAbsolutePath 获取绝对路径
func GetAbsolutePath(relPath string) string {
	if relPath == "." || relPath == "" {
		return GetRootPath()
	}
	absPath := filepath.Join(GetRootPath(), relPath)
	absPath, _ = filepath.Abs(absPath)
	return absPath
}

// SetTitle 设置页面标题
func SetTitle(title string) {
	if title != "" {
		pageTitle = title
	}
}

// GetTitle 获取页面标题
func GetTitle() string {
	return pageTitle
}

// GetAdminUsername 获取管理员用户名
func GetAdminUsername() string {
	return DefaultUsername
}

// md5Hash MD5 加密
func md5Hash(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

// sendSuccess 发送成功响应
func sendSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	response := APIResponse{
		Code:    0,
		Message: "success",
		Data:    data,
	}
	json.NewEncoder(w).Encode(response)
}

// sendError 发送错误响应
func sendError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response := APIResponse{
		Code:    code,
		Message: message,
		Data:    nil,
	}
	json.NewEncoder(w).Encode(response)
}

// isSubPath 检查路径是否在允许的目录内
func isSubPath(path string) bool {
	// 如果设置了 rootPath，使用它；否则使用当前工作目录
	allowedDir := rootPath
	if allowedDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return false
		}
		allowedDir = cwd
	}

	// 获取允许目录的绝对路径
	absAllowed, err := filepath.Abs(allowedDir)
	if err != nil {
		return false
	}

	// 处理相对路径 "." 或 ""
	if path == "." || path == "" {
		// 相对路径相对于允许目录
		absPath := absAllowed
		return absPath == absAllowed
	}

	// 将路径转为绝对路径（相对于允许目录）
	absPath := filepath.Join(absAllowed, path)
	absPath, err = filepath.Abs(absPath)
	if err != nil {
		return false
	}

	// 简单的安全检查：路径必须在允许目录下
	return strings.HasPrefix(absPath, absAllowed) || absPath == absAllowed
}

// getFileType 根据扩展名获取文件类型
func getFileType(ext string, isDir bool) string {
	if isDir {
		return "文件夹"
	}

	imageExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".bmp": true, ".webp": true, ".svg": true, ".ico": true,
	}

	videoExts := map[string]bool{
		".mp4": true, ".avi": true, ".mkv": true, ".mov": true,
		".wmv": true, ".flv": true, ".webm": true, ".m3u8": true,
	}

	audioExts := map[string]bool{
		".mp3": true, ".wav": true, ".ogg": true, ".flac": true,
		".aac": true, ".m4a": true, ".wma": true,
	}

	docExts := map[string]bool{
		".pdf": true, ".doc": true, ".docx": true, ".xls": true,
		".xlsx": true, ".ppt": true, ".pptx": true, ".txt": true,
		".rtf": true, ".odt": true, ".csv": true,
	}

	codeExts := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".py": true,
		".java": true, ".c": true, ".cpp": true, ".h": true,
		".rs": true, ".php": true, ".rb": true, ".swift": true,
		".kt": true, ".html": true, ".css": true, ".scss": true,
		".json": true, ".xml": true, ".yaml": true, ".yml": true,
		".md": true, ".sh": true, ".sql": true, ".vue": true,
	}

	zipExts := map[string]bool{
		".zip": true, ".7z": true, ".rar": true, ".tar": true,
		".gz": true, ".bz2": true, ".xz": true, ".tgz": true,
	}

	if _, ok := imageExts[ext]; ok {
		return "图片"
	}
	if _, ok := videoExts[ext]; ok {
		return "视频"
	}
	if _, ok := audioExts[ext]; ok {
		return "音频"
	}
	if _, ok := docExts[ext]; ok {
		return "文档"
	}
	if _, ok := codeExts[ext]; ok {
		return "代码"
	}
	if _, ok := zipExts[ext]; ok {
		return "压缩包"
	}

	return "文件"
}

// formatFileSize 格式化文件大小
func FormatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
