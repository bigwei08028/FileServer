package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"file-server/handler"
)

//go:embed all:static favicon.ico
var staticFiles embed.FS

var (
	port     = flag.String("p", "8902", "端口号")
	rootPath = flag.String("r", "", "根目录路径")
	title    = flag.String("t", "FileServer - 内网文件服务", "页面标题")
	username = flag.String("u", "admin", "用户名")
	password = flag.String("w", "admin", "密码")
	noAuth   = flag.Bool("no-auth", false, "禁用登录认证")
)

func main() {
	flag.Parse()

	// 获取可执行文件所在目录
	exeFile, err := os.Executable()
	if err != nil {
		log.Fatalf("获取可执行文件路径失败: %v", err)
	}
	exeDir := filepath.Dir(exeFile)

	// 获取文件存储根目录
	filesPath := *rootPath
	if filesPath == "" {
		// 默认使用可执行文件所在目录下的 files 文件夹
		filesPath = filepath.Join(exeDir, "files")
	}
	absPath, err := filepath.Abs(filesPath)
	if err != nil {
		log.Fatalf("获取路径失败: %v", err)
	}

	// 检查文件目录是否存在
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		log.Printf("文件目录不存在，将自动创建: %s", absPath)
		os.MkdirAll(absPath, 0755)
	}

	// 设置页面标题
	handler.SetTitle(*title)
	handler.SetRootPath(absPath)

	// 设置用户凭据
	handler.SetUserCredentials(*username, *password)

	// 初始化日志系统
	handler.InitLog()

	// 检查是否有外部静态文件目录（与 exe 同级）
	externalStaticDir := filepath.Join(exeDir, "static")
	useExternalStatic := false
	if _, err := os.Stat(filepath.Join(exeDir, "index.html")); err == nil {
		// 同级目录有 index.html，使用外部静态文件
		useExternalStatic = true
	} else if _, err := os.Stat(externalStaticDir); err == nil {
		// 同级目录有 static 文件夹，使用外部静态文件
		useExternalStatic = true
	}

	var staticFS http.Handler
	if useExternalStatic {
		// 使用外部静态文件目录（只serve static/文件夹）
		staticFS = http.FileServer(http.Dir(externalStaticDir))
		log.Printf("使用外部静态文件目录: %s", externalStaticDir)
	} else {
		// 使用嵌入的静态文件
		subFS, err := fs.Sub(staticFiles, "static")
		if err != nil {
			log.Fatalf("获取静态文件系统失败: %v", err)
		}
		staticFS = http.FileServer(http.FS(subFS))
		log.Printf("使用内置静态文件")
	}

	// 从项目目录提供静态文件
	http.Handle("/", staticFS)

	// favicon.ico
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("favicon.ico")
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(data)
	})

	// 登录接口（无需认证）
	http.HandleFunc("/api/login", handler.Login)

	// 日志接口（无需认证，用于前端页面访问等日志）
	http.HandleFunc("/api/log", handler.FrontendLog)

	// 需要认证的 API
	apiHandlers := map[string]func(http.ResponseWriter, *http.Request){
		"/api/verify":        handler.VerifyToken,
		"/api/list":          handler.ListFiles,
		"/api/upload":        handler.UploadFile,
		"/api/upload-folder": handler.UploadFolder,
		"/api/delete":        handler.DeleteFile,
		"/api/mkdir":         handler.CreateFolder,
		"/api/rename":        handler.RenameFile,
		"/api/info":          handler.GetFileInfo,
		"/api/download":      handler.DownloadFile,
		"/api/dirs-tree":     handler.GetDirsTree,
	}

	// 用户管理 API（仅管理员可访问）
	userApiHandlers := map[string]func(http.ResponseWriter, *http.Request){
		"/api/users":       handler.GetUsers,
		"/api/users/create": handler.CreateUser,
		"/api/users/update": handler.UpdateUser,
		"/api/users/delete": handler.DeleteUser,
		"/api/users/reset-password": handler.ResetPassword,
	}

	// 用户修改自己密码的 API（需要登录认证）
	http.HandleFunc("/api/users/change-password", authMiddleware(handler.ChangePassword))

	// 获取当前用户信息 API（需要登录认证）
	http.HandleFunc("/api/users/me", authMiddleware(handler.GetCurrentUser))

	for path, handlerFunc := range userApiHandlers {
		if *noAuth {
			http.HandleFunc(path, handlerFunc)
		} else {
			http.HandleFunc(path, adminMiddleware(handlerFunc))
		}
	}

	for path, handlerFunc := range apiHandlers {
		if *noAuth {
			http.HandleFunc(path, handlerFunc)
		} else {
			http.HandleFunc(path, authMiddleware(handlerFunc))
		}
	}

	// 启动服务器
	addr := fmt.Sprintf(":%s", *port)
	if *noAuth {
		log.Printf("警告: 登录认证已禁用!")
	}
	log.Printf("文件服务器启动成功!")
	log.Printf("访问地址: http://localhost:%s", *port)
	log.Printf("文件根目录: %s", absPath)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}

// authMiddleware 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"code":401,"message":"未授权"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		_, err := handler.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, `{"code":401,"message":"令牌无效或已过期"}`, http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// adminMiddleware 管理员认证中间件
func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"code":401,"message":"未授权"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := handler.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, `{"code":401,"message":"令牌无效或已过期"}`, http.StatusUnauthorized)
			return
		}

		// 检查是否是管理员
		if claims.Username != handler.GetAdminUsername() {
			http.Error(w, `{"code":403,"message":"只有管理员可以执行此操作"}`, http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
