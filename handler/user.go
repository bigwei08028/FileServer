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
	"sync"
	"time"
)

// DirAccess 目录访问权限结构
type DirAccess struct {
	Path     string `json:"path"`      // 相对路径
	IsReadOnly bool `json:"isReadOnly"` // 是否只读
}

// User 用户结构
type User struct {
	ID           string      `json:"id"`
	Username     string      `json:"username"`
	PasswordMD5  string      `json:"passwordMd5"`
	CreatedAt    time.Time   `json:"createdAt"`
	UpdatedAt    time.Time   `json:"updatedAt"`
	IsDisabled   bool        `json:"isDisabled"`
	DirAccess    []DirAccess `json:"dirAccess"`    // 目录访问权限列表
}

// UserRequest 用户请求结构
type UserRequest struct {
	Username  string      `json:"username"`
	Password  string      `json:"password"`
	DirAccess []DirAccess `json:"dirAccess"`
}

// UserUpdateRequest 用户更新请求结构
type UserUpdateRequest struct {
	Password   string      `json:"password"`
	DirAccess  []DirAccess `json:"dirAccess"`
	IsDisabled bool        `json:"isDisabled"`
}

// usersMutex 用户数据读写锁
var usersMutex sync.RWMutex

// usersMap 用户内存存储
var usersMap map[string]*User
var userIndex int

// getUsersFilePath 获取用户数据文件路径
func getUsersFilePath() string {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	return filepath.Join(exeDir, "data", "users.json")
}

// loadUsers 从文件加载用户数据
func loadUsers() error {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	// 如果已经加载过，直接返回
	if usersMap != nil {
		return nil
	}

	usersFile := getUsersFilePath()
	fmt.Printf("用户文件路径: %s\n", usersFile)

	// 确保目录存在
	dir := filepath.Dir(usersFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	usersMap = make(map[string]*User)
	userIndex = 1

	// 如果文件不存在，创建默认管理员用户
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		// 创建默认管理员用户（* 表示可访问所有目录）
		adminUser := &User{
			ID:            generateUserID(),
			Username:      DefaultUsername,
			PasswordMD5:   Md5Hash(DefaultPassword),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			IsDisabled:    false,
			DirAccess:     []DirAccess{{Path: "*", IsReadOnly: false}},
		}
		usersMap[adminUser.Username] = adminUser
		fmt.Printf("创建管理员用户: %s, 密码Hash: %s\n", adminUser.Username, adminUser.PasswordMD5)

		// 保存到文件
		if err := saveUsersToFile(); err != nil {
			return err
		}
		return nil
	}

	// 读取用户数据
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, &usersMap); err != nil {
		return err
	}

	// 检查管理员密码是否为空（兼容旧数据）
	if admin, exists := usersMap[DefaultUsername]; exists {
		if admin.PasswordMD5 == "" {
			admin.PasswordMD5 = Md5Hash(DefaultPassword)
			fmt.Printf("管理员密码为空，使用默认密码重新设置\n")
			saveUsersToFile()
		}
	}

	fmt.Printf("从文件加载用户: %v\n", usersMap)
	return nil
}

// saveUsersToFile 保存用户数据到文件
func saveUsersToFile() error {
	usersFile := getUsersFilePath()

	// 确保目录存在
	dir := filepath.Dir(usersFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(usersMap, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(usersFile, data, 0644)
}

// generateUserID 生成用户ID
func generateUserID() string {
	id := userIndex
	userIndex++
	return "user_" + string(rune('a'+id%26)) + string(rune('a'+(id/26)%26)) + time.Now().Format("02030405")
}

// Md5Hash MD5 加密
func Md5Hash(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

// GetUsers 获取所有用户列表
func GetUsers(w http.ResponseWriter, r *http.Request) {
	// 检查是否是管理员
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && len(authHeader) > 7 {
		claims, err := ValidateToken(authHeader[7:])
		if err != nil || claims.Username != DefaultUsername {
			sendError(w, "只有管理员可以查看用户列表", http.StatusForbidden)
			return
		}
	}

	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	usersMutex.RLock()
	defer usersMutex.RUnlock()

	// 转换为列表，排除密码
	var userList []User
	for _, u := range usersMap {
		userList = append(userList, User{
			ID:            u.ID,
			Username:      u.Username,
			PasswordMD5:  "", // 不返回密码
			CreatedAt:     u.CreatedAt,
			UpdatedAt:     u.UpdatedAt,
			IsDisabled:    u.IsDisabled,
			DirAccess:     u.DirAccess,
		})
	}

	sendSuccess(w, userList)
}

// CreateUser 创建新用户
func CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否是管理员
	authHeader := r.Header.Get("Authorization")
	var claims *Claims
	if authHeader != "" && len(authHeader) > 7 {
		var err error
		claims, err = ValidateToken(authHeader[7:])
		if err != nil || claims.Username != DefaultUsername {
			sendError(w, "只有管理员可以创建用户", http.StatusForbidden)
			return
		}
	} else {
		sendError(w, "未授权", http.StatusUnauthorized)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.Username == "" {
		sendError(w, "用户名不能为空", http.StatusBadRequest)
		return
	}
	if len(req.Username) < 3 || len(req.Username) > 20 {
		sendError(w, "用户名长度必须在3-20之间", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		sendError(w, "密码不能为空", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 6 {
		sendError(w, "密码长度必须至少6位", http.StatusBadRequest)
		return
	}

	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败", http.StatusInternalServerError)
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	// 检查用户名是否已存在
	if _, exists := usersMap[req.Username]; exists {
		sendError(w, "用户名已存在", http.StatusConflict)
		return
	}

	// 创建新用户
	newUser := &User{
		ID:            generateUserID(),
		Username:      req.Username,
		PasswordMD5:   Md5Hash(req.Password),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		IsDisabled:    false,
		DirAccess:     req.DirAccess,
	}

	usersMap[req.Username] = newUser

	if err := saveUsersToFile(); err != nil {
		sendError(w, "保存用户数据失败", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"id":       newUser.ID,
		"username": newUser.Username,
		"message":  "用户创建成功",
	})
}

// UpdateUser 更新用户
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否是管理员
	authHeader := r.Header.Get("Authorization")
	var claims *Claims
	if authHeader != "" && len(authHeader) > 7 {
		var err error
		claims, err = ValidateToken(authHeader[7:])
		if err != nil || claims.Username != DefaultUsername {
			sendError(w, "只有管理员可以更新用户", http.StatusForbidden)
			return
		}
	} else {
		sendError(w, "未授权", http.StatusUnauthorized)
		return
	}

	var req UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	// 从 URL 获取用户名
	path := r.URL.Query().Get("username")
	if path == "" {
		sendError(w, "缺少用户名参数", http.StatusBadRequest)
		return
	}

	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败", http.StatusInternalServerError)
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	user, exists := usersMap[path]
	if !exists {
		sendError(w, "用户不存在", http.StatusNotFound)
		return
	}

	// 不能禁用或删除管理员
	if path == DefaultUsername {
		sendError(w, "不能修改管理员账户", http.StatusForbidden)
		return
	}

	// 更新密码（如果提供）
	if req.Password != "" {
		if len(req.Password) < 6 {
			sendError(w, "密码长度必须至少6位", http.StatusBadRequest)
			return
		}
		user.PasswordMD5 = Md5Hash(req.Password)
	}

	// 更新其他字段
	user.DirAccess = req.DirAccess
	user.IsDisabled = req.IsDisabled
	user.UpdatedAt = time.Now()

	if err := saveUsersToFile(); err != nil {
		sendError(w, "保存用户数据失败", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"username": user.Username,
		"message":  "用户更新成功",
	})
}

// DeleteUser 删除用户
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否是管理员
	authHeader := r.Header.Get("Authorization")
	var claims *Claims
	if authHeader != "" && len(authHeader) > 7 {
		var err error
		claims, err = ValidateToken(authHeader[7:])
		if err != nil || claims.Username != DefaultUsername {
			sendError(w, "只有管理员可以删除用户", http.StatusForbidden)
			return
		}
	} else {
		sendError(w, "未授权", http.StatusUnauthorized)
		return
	}

	// 从 URL 获取用户名
	path := r.URL.Query().Get("username")
	if path == "" {
		sendError(w, "缺少用户名参数", http.StatusBadRequest)
		return
	}

	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败", http.StatusInternalServerError)
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	// 不能删除管理员
	if path == DefaultUsername {
		sendError(w, "不能删除管理员账户", http.StatusForbidden)
		return
	}

	user, exists := usersMap[path]
	if !exists {
		sendError(w, "用户不存在", http.StatusNotFound)
		return
	}

	delete(usersMap, path)

	if err := saveUsersToFile(); err != nil {
		sendError(w, "保存用户数据失败", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"username": user.Username,
		"message":  "用户删除成功",
	})
}

// ResetPassword 重置用户密码
func ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 检查是否是管理员
	authHeader := r.Header.Get("Authorization")
	var claims *Claims
	if authHeader != "" && len(authHeader) > 7 {
		var err error
		claims, err = ValidateToken(authHeader[7:])
		if err != nil || claims.Username != DefaultUsername {
			sendError(w, "只有管理员可以重置密码", http.StatusForbidden)
			return
		}
	} else {
		sendError(w, "未授权", http.StatusUnauthorized)
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

	if req.Username == "" || req.Password == "" {
		sendError(w, "用户名和密码不能为空", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		sendError(w, "密码长度必须至少6位", http.StatusBadRequest)
		return
	}

	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败", http.StatusInternalServerError)
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	user, exists := usersMap[req.Username]
	if !exists {
		sendError(w, "用户不存在", http.StatusNotFound)
		return
	}

	user.PasswordMD5 = Md5Hash(req.Password)
	user.UpdatedAt = time.Now()

	if err := saveUsersToFile(); err != nil {
		sendError(w, "保存用户数据失败", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"username": user.Username,
		"message":  "密码重置成功",
	})
}

// CheckUserAccess 检查用户是否有权限访问指定路径
func CheckUserAccess(username, path string) (bool, bool) {
	// 管理员有所有权限
	if username == DefaultUsername {
		return true, false
	}

	if err := loadUsers(); err != nil {
		return false, false
	}

	usersMutex.RLock()
	defer usersMutex.RUnlock()

	user, exists := usersMap[username]
	if !exists {
		return false, false
	}

	// 检查用户是否被禁用
	if user.IsDisabled {
		return false, false
	}

	// 检查是否有访问权限
	hasAccess := false
	isReadOnly := false
	for _, dirAccess := range user.DirAccess {
		if dirAccess.Path == "*" {
			hasAccess = true
			isReadOnly = dirAccess.IsReadOnly
			break
		}

		// 获取 rootPath 的绝对路径
		absRootPath, _ := filepath.Abs(GetRootPath())

		// 将 path 转换为相对路径
		relPath, err := filepath.Rel(absRootPath, path)
		if err != nil {
			continue
		}

		// 使用 filepath.Separator 处理路径分隔符
		// 检查相对路径是否以 dir 开头（支持带或不带斜杠的情况）
		if strings.HasPrefix(relPath, dirAccess.Path) ||
			strings.HasPrefix(relPath, dirAccess.Path+string(filepath.Separator)) ||
			relPath == dirAccess.Path {
			hasAccess = true
			isReadOnly = dirAccess.IsReadOnly
			break
		}
	}

	if !hasAccess {
		return false, false
	}

	// 返回是否为只读
	return true, isReadOnly
}

// GetFirstAccessibleDir 获取用户有权访问的第一个目录
func GetFirstAccessibleDir(username string) string {
	// 管理员可以访问根目录
	if username == DefaultUsername {
		return "."
	}

	if err := loadUsers(); err != nil {
		return ""
	}

	usersMutex.RLock()
	defer usersMutex.RUnlock()

	user, exists := usersMap[username]
	if !exists {
		return ""
	}

	// 如果用户被禁用
	if user.IsDisabled {
		return ""
	}

	// 返回第一个可访问目录
	for _, dirAccess := range user.DirAccess {
		if dirAccess.Path == "*" {
			return "."
		}
		if dirAccess.Path != "" {
			return dirAccess.Path
		}
	}

	return ""
}

// GetCurrentUser 获取当前登录用户信息
func GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// 从 Authorization header 获取用户名
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) <= 7 {
		sendError(w, "未授权", http.StatusUnauthorized)
		return
	}

	claims, err := ValidateToken(authHeader[7:])
	if err != nil {
		sendError(w, "令牌无效", http.StatusUnauthorized)
		return
	}

	username := claims.Username

	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	usersMutex.RLock()
	user, exists := usersMap[username]
	usersMutex.RUnlock()

	if !exists {
		sendError(w, "用户不存在", http.StatusNotFound)
		return
	}

	// 返回用户信息（不包含密码）
	sendSuccess(w, map[string]interface{}{
		"id":        user.ID,
		"username":  user.Username,
		"isAdmin":   username == DefaultUsername,
		"isDisabled": user.IsDisabled,
		"dirAccess": user.DirAccess,
	})
}

// ChangePassword 用户修改自己的密码
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "只支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 检查用户是否已登录
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) <= 7 {
		sendError(w, "未授权", http.StatusUnauthorized)
		return
	}

	claims, err := ValidateToken(authHeader[7:])
	if err != nil {
		sendError(w, "令牌无效", http.StatusUnauthorized)
		return
	}

	username := claims.Username

	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "无效的请求", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.OldPassword == "" {
		sendError(w, "请输入当前密码", http.StatusBadRequest)
		return
	}
	if req.NewPassword == "" {
		sendError(w, "请输入新密码", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 6 {
		sendError(w, "新密码长度必须至少6位", http.StatusBadRequest)
		return
	}

	if err := loadUsers(); err != nil {
		sendError(w, "加载用户数据失败", http.StatusInternalServerError)
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	user, exists := usersMap[username]
	if !exists {
		sendError(w, "用户不存在", http.StatusNotFound)
		return
	}

	// 验证当前密码
	if user.PasswordMD5 != Md5Hash(req.OldPassword) {
		sendError(w, "当前密码错误", http.StatusBadRequest)
		return
	}

	// 更新密码
	user.PasswordMD5 = Md5Hash(req.NewPassword)
	user.UpdatedAt = time.Now()

	if err := saveUsersToFile(); err != nil {
		sendError(w, "保存用户数据失败", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"message": "密码修改成功",
	})
}
