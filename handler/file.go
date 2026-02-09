package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"file-server/utils"
)

// percentEncodeRFC5987 对字符串进行 RFC 5987 百分号编码
func percentEncodeRFC5987(s string) string {
	result := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			result += string(c)
		} else {
			for _, b := range []byte(string(c)) {
				result += fmt.Sprintf("%%%02X", b)
			}
		}
	}
	return result
}

// FileInfo 文件信息结构
type FileInfo struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`         // 相对路径（相对于 rootPath）
	FullPath     string    `json:"fullPath"`     // 绝对路径
	RelativePath string    `json:"relativePath"` // 从 rootPath 开始的相对路径
	IsDir        bool      `json:"isDir"`
	Size         int64     `json:"size"`
	ModifiedTime time.Time `json:"modifiedTime"`
	Extension    string    `json:"extension"`
	Type         string    `json:"type"`
}

// APIResponse API 响应结构
type APIResponse struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    interface{} `json:"data"`
}

// getUsernameFromRequest 从请求中获取用户名
func getUsernameFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	fmt.Printf("getUsernameFromRequest: authHeader=%s\n", authHeader)
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateToken(tokenString)
		fmt.Printf("getUsernameFromRequest: claims=%v, err=%v\n", claims, err)
		if err == nil && claims != nil {
			return claims.Username
		}
	}
	return ""
}

// ListFiles 列出目录文件
func ListFiles(w http.ResponseWriter, r *http.Request) {
	// 获取请求的路径
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "."
	}

	// 如果 rootPath 为空，设置为当前目录
	if rootPath == "" {
		rootPath, _ = os.Getwd()
	}

	// 获取绝对路径（相对于 rootPath）
	absPath := filepath.Join(rootPath, path)
	absPath, err := filepath.Abs(absPath)
	if err != nil {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查路径是否在允许的目录内
	if !isSubPath(absPath) {
		sendError(w, "访问被拒绝", http.StatusForbidden)
		return
	}

	// 获取当前用户名和只读状态
	username := getUsernameFromRequest(r)
	isReadOnly := false
	fmt.Printf("ListFiles: username=%s, path=%s\n", username, path)
	if username != "" {
		hasAccess, readOnly := CheckUserAccess(username, absPath)
		isReadOnly = readOnly
		fmt.Printf("ListFiles: hasAccess=%v, isReadOnly=%v\n", hasAccess, isReadOnly)
		if !hasAccess {
			// 检查是否是请求根目录且用户没有 * 权限
			if path == "." {
				// 重定向到用户有权访问的第一个目录
				firstDir := GetFirstAccessibleDir(username)
				fmt.Printf("ListFiles: redirect to firstDir=%s\n", firstDir)
				if firstDir != "" {
					sendSuccess(w, map[string]interface{}{
						"redirect":  firstDir,
						"message":  "您只能访问特定目录，已自动跳转到可访问目录",
						"isReadOnly": isReadOnly,
					})
					return
				}
			}
			sendError(w, "无权访问此目录", http.StatusForbidden)
			return
		}
	}

	// 检查目录是否存在
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		sendError(w, "目录不存在", http.StatusNotFound)
		return
	}

	// 读取目录
	files, err := os.ReadDir(absPath)
	if err != nil {
		sendError(w, "无法读取目录: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 获取 rootPath 的绝对路径
	absRootPath, _ := filepath.Abs(rootPath)

	// 构建文件列表
	var fileList []FileInfo
	for _, file := range files {
		filePath := filepath.Join(absPath, file.Name())
		info, err := file.Info()
		if err != nil {
			continue
		}

		// 计算相对路径（从 rootPath 开始）
		relPath, _ := filepath.Rel(absRootPath, filePath)

		ext := strings.ToLower(filepath.Ext(file.Name()))
		fileInfo := FileInfo{
			Name:         file.Name(),
			Path:         relPath,
			FullPath:     filePath,
			RelativePath: relPath,
			IsDir:        file.IsDir(),
			Size:         info.Size(),
			ModifiedTime: info.ModTime(),
			Extension:    ext,
			Type:         getFileType(ext, file.IsDir()),
		}

		fileList = append(fileList, fileInfo)
	}

	// 返回文件列表和只读状态
	sendSuccess(w, map[string]interface{}{
		"files":     fileList,
		"isReadOnly": isReadOnly,
	})
}

// UploadFile 上传单个文件
func UploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 解析表单
	err := r.ParseMultipartForm(32 << 20) // 32MB
	if err != nil {
		sendError(w, "解析表单失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 获取目标路径
	path := r.FormValue("path")
	if path == "" {
		path = "."
	}

	absPath := GetAbsolutePath(path)
	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查用户权限
	username := getUsernameFromRequest(r)
	if username != "" {
		hasAccess, isReadOnly := CheckUserAccess(username, absPath)
		if !hasAccess {
			sendError(w, "无权访问此目录", http.StatusForbidden)
			return
		}
		if isReadOnly {
			sendError(w, "只读模式，无法上传文件", http.StatusForbidden)
			return
		}
	}

	// 确保目录存在
	if err := os.MkdirAll(absPath, 0755); err != nil {
		sendError(w, "创建目录失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 获取上传的文件
	file, handler, err := r.FormFile("file")
	if err != nil {
		sendError(w, "获取文件失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 创建目标文件
	dstPath := filepath.Join(absPath, handler.Filename)
	dst, err := os.Create(dstPath)
	if err != nil {
		sendError(w, "创建文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// 复制文件内容
	if _, err := io.Copy(dst, file); err != nil {
		os.Remove(dstPath)
		sendError(w, "保存文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sendSuccess(w, map[string]string{
		"name": handler.Filename,
		"path": dstPath,
	})
}

// UploadFolder 上传文件夹（ZIP格式）
func UploadFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 解析表单
	err := r.ParseMultipartForm(512 << 20) // 512MB
	if err != nil {
		sendError(w, "解析表单失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 获取目标路径
	path := r.FormValue("path")
	if path == "" {
		path = "."
	}

	absPath := GetAbsolutePath(path)
	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查用户权限
	username := getUsernameFromRequest(r)
	if username != "" {
		hasAccess, isReadOnly := CheckUserAccess(username, absPath)
		if !hasAccess {
			sendError(w, "无权访问此目录", http.StatusForbidden)
			return
		}
		if isReadOnly {
			sendError(w, "只读模式，无法上传文件夹", http.StatusForbidden)
			return
		}
	}

	// 确保目录存在
	if err := os.MkdirAll(absPath, 0755); err != nil {
		sendError(w, "创建目录失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 获取上传的ZIP文件
	file, handler, err := r.FormFile("file")
	if err != nil {
		sendError(w, "获取文件失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 保存临时ZIP文件
	tempZip := filepath.Join(os.TempDir(), "upload_"+time.Now().Format("20060102150405")+"_"+handler.Filename)
	dst, err := os.Create(tempZip)
	if err != nil {
		sendError(w, "创建临时文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempZip)

	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		sendError(w, "保存临时文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	dst.Close()

	// 解压到目标目录
	if err := utils.UnzipFolder(tempZip, absPath); err != nil {
		sendError(w, "解压失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sendSuccess(w, map[string]string{
		"name": handler.Filename,
		"path": absPath,
	})
}

// DeleteFile 删除文件或文件夹
func DeleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	absPath := GetAbsolutePath(req.Path)
	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查用户权限
	username := getUsernameFromRequest(r)
	if username != "" {
		hasAccess, isReadOnly := CheckUserAccess(username, absPath)
		if !hasAccess {
			sendError(w, "无权访问此目录", http.StatusForbidden)
			return
		}
		if isReadOnly {
			sendError(w, "只读模式，无法删除文件", http.StatusForbidden)
			return
		}
	}

	// 检查是文件还是目录
	info, err := os.Stat(absPath)
	if err != nil {
		sendError(w, "文件不存在", http.StatusNotFound)
		return
	}

	// 删除
	if info.IsDir() {
		if err := os.RemoveAll(absPath); err != nil {
			sendError(w, "删除目录失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 记录删除目录日志
		if username != "" {
			LogOperation(username, OpDelete, "删除目录: "+req.Path)
		}
	} else {
		if err := os.Remove(absPath); err != nil {
			sendError(w, "删除文件失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 记录删除文件日志
		if username != "" {
			LogOperation(username, OpDelete, "删除文件: "+req.Path)
		}
	}

	sendSuccess(w, nil)
}

// CreateFolder 创建文件夹
func CreateFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	absPath := GetAbsolutePath(req.Path)
	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查用户权限
	username := getUsernameFromRequest(r)
	if username != "" {
		hasAccess, isReadOnly := CheckUserAccess(username, absPath)
		if !hasAccess {
			sendError(w, "无权访问此目录", http.StatusForbidden)
			return
		}
		if isReadOnly {
			sendError(w, "只读模式，无法创建文件夹", http.StatusForbidden)
			return
		}
	}

	// 创建目录
	newPath := filepath.Join(absPath, req.Name)
	if err := os.MkdirAll(newPath, 0755); err != nil {
		sendError(w, "创建目录失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 记录创建文件夹日志（username 已在上面定义）
	if username != "" {
		LogOperation(username, OpCreateDir, "创建文件夹: "+newPath)
	}

	sendSuccess(w, map[string]string{
		"path": newPath,
	})
}

// RenameFile 重命名文件或文件夹
func RenameFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path    string `json:"path"`
		NewName string `json:"newName"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	absPath := GetAbsolutePath(req.Path)
	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查用户权限
	username := getUsernameFromRequest(r)
	if username != "" {
		hasAccess, isReadOnly := CheckUserAccess(username, absPath)
		if !hasAccess {
			sendError(w, "无权访问此目录", http.StatusForbidden)
			return
		}
		if isReadOnly {
			sendError(w, "只读模式，无法重命名文件", http.StatusForbidden)
			return
		}
	}

	newPath := filepath.Join(filepath.Dir(absPath), req.NewName)
	if err := os.Rename(absPath, newPath); err != nil {
		sendError(w, "重命名失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 记录重命名日志
	if username != "" {
		LogOperation(username, OpRename, "重命名: "+req.Path+" -> "+req.NewName)
	}

	sendSuccess(w, map[string]string{
		"path": newPath,
	})
}

// GetFileInfo 获取文件详细信息
func GetFileInfo(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		sendError(w, "缺少路径参数", http.StatusBadRequest)
		return
	}

	absPath := GetAbsolutePath(path)
	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(absPath)
	if err != nil {
		sendError(w, "文件不存在", http.StatusNotFound)
		return
	}

	fileInfo := FileInfo{
		Name:         info.Name(),
		Path:         absPath,
		IsDir:        info.IsDir(),
		Size:         info.Size(),
		ModifiedTime: info.ModTime(),
		Extension:    strings.ToLower(filepath.Ext(info.Name())),
		Type:         getFileType(strings.ToLower(filepath.Ext(info.Name())), info.IsDir()),
	}

	sendSuccess(w, fileInfo)
}

// DownloadFile 下载文件
func DownloadFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		sendError(w, "缺少路径参数", http.StatusBadRequest)
		return
	}

	absPath := GetAbsolutePath(path)
	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查文件是否存在
	info, err := os.Stat(absPath)
	if err != nil {
		sendError(w, "文件不存在", http.StatusNotFound)
		return
	}

	if info.IsDir() {
		sendError(w, "不支持下载目录", http.StatusBadRequest)
		return
	}

	// 记录下载日志
	username := getUsernameFromRequest(r)
	if username == "" {
		username = "匿名用户"
	}
	clientIP := r.RemoteAddr
	LogOperation(username, OpDownload, "下载文件: "+path+" - IP: "+clientIP)

	// 设置响应头 - 使用 RFC 5987 编码处理中文文件名
	encodedFilename := percentEncodeRFC5987(info.Name())
	w.Header().Set("Content-Disposition", "attachment; filename=\""+encodedFilename+"\"; filename*=UTF-8''"+encodedFilename)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	// 发送文件
	http.ServeFile(w, r, absPath)
}

// DirNode 目录节点结构
type DirNode struct {
	Name     string     `json:"name"`
	Path     string     `json:"path"`
	IsDir    bool       `json:"isDir"`
	Children []DirNode  `json:"children,omitempty"`
}

// GetDirsTree 获取目录树（用于目录选择器）
func GetDirsTree(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "."
	}

	fmt.Printf("GetDirsTree: path=%s\n", path)

	absPath := GetAbsolutePath(path)
	fmt.Printf("GetDirsTree: absPath=%s\n", absPath)

	if !isSubPath(absPath) {
		sendError(w, "无效的路径", http.StatusBadRequest)
		return
	}

	// 检查目录是否存在
	info, err := os.Stat(absPath)
	if err != nil {
		sendError(w, "目录不存在", http.StatusNotFound)
		return
	}

	if !info.IsDir() {
		sendError(w, "路径不是目录", http.StatusBadRequest)
		return
	}

	// 递归获取目录树
	tree := buildDirTree(absPath, absPath)
	fmt.Printf("GetDirsTree: tree=%+v\n", tree)
	sendSuccess(w, tree)
}

// buildDirTree 递归构建目录树
func buildDirTree(rootPath, currentPath string) DirNode {
	name := filepath.Base(currentPath)
	relPath := getRelativePathFromRoot(rootPath, currentPath)

	node := DirNode{
		Name:  name,
		Path:  relPath,
		IsDir: true,
	}

	fmt.Printf("buildDirTree: currentPath=%s, name=%s, relPath=%s\n", currentPath, name, relPath)

	// 读取目录
	files, err := os.ReadDir(currentPath)
	if err != nil {
		fmt.Printf("buildDirTree: error reading dir: %v\n", err)
		return node
	}

	for _, file := range files {
		fmt.Printf("buildDirTree: file=%s, IsDir=%v\n", file.Name(), file.IsDir())
		if file.IsDir() {
			childPath := filepath.Join(currentPath, file.Name())
			childNode := buildDirTree(rootPath, childPath)
			node.Children = append(node.Children, childNode)
		}
	}

	return node
}

// getRelativePathFromRoot 获取相对于rootPath的路径
func getRelativePathFromRoot(rootPath, fullPath string) string {
	relPath, err := filepath.Rel(rootPath, fullPath)
	if err != nil {
		return fullPath
	}
	if relPath == "." {
		return "."
	}
	return relPath
}
