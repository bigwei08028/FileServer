# FileServer - 内网文件服务

一个基于 Go 语言开发的轻量级内网文件服务器，提供文件浏览、上传、下载、管理等功能，支持多用户管理和权限控制。

## 功能特性

### 文件管理
- **文件浏览**: 以列表形式显示目录内容，支持文件夹和文件分类显示
- **文件上传**: 支持单文件上传，最大限制 32MB
- **文件夹上传**: 支持 ZIP 格式文件夹上传，最大限制 512MB
- **文件下载**: 支持单个文件下载，完美支持中文文件名（RFC 5987 编码）
- **新建文件夹**: 在当前目录下创建新文件夹
- **重命名**: 支持文件和文件夹重命名
- **删除**: 支持批量删除文件和文件夹
- **目录树**: 查看完整目录树结构，方便导航

### 用户管理
- **多用户支持**: 支持创建多个用户账号
- **权限控制**:
  - 管理员可访问所有目录
  - 普通用户可配置指定目录的访问权限
  - 支持只读模式设置
- **用户禁用**: 可禁用用户账号，禁止其访问
- **密码管理**:
  - 管理员可重置用户密码
  - 用户可自行修改密码

### 界面特性
- **深色/浅色模式**: 一键切换明暗主题
- **响应式设计**: 适配不同屏幕尺寸
- **中文支持**: 完整的中文界面和文件名支持
- **文件类型图标**: 根据文件类型显示对应的图标
- **批量操作**: 支持选中多个文件进行批量删除
- **文件名显示**: 完整显示文件名，超出宽度自动截断
- **文件搜索**: 支持文件名模糊搜索，快速定位文件

### 技术特性
- **单文件部署**: 编译后为单一可执行文件，易于部署
- **嵌入静态资源**: 前端资源编译进二进制文件，无需额外文件
- **外部静态资源支持**: 支持使用外部静态文件进行自定义
- **JWT 认证**: 基于 Token 的安全认证机制
- **操作日志**: 记录所有用户操作日志（登录、退出、访问、下载、上传、重命名、删除等）
- **跨平台**: 支持 Windows、Linux、macOS 等操作系统

## 安装与运行

### 方式一：直接运行（需要安装 Go）

```bash
# 克隆项目
git clone <repository-url>
cd file_servers_go

# 运行
go run main.go
```

### 方式二：编译运行

```bash
# 编译为当前平台的二进制文件
go build -o fileserver.exe main.go   # Windows
# 或
go build -o fileserver main.go        # Linux/macOS

# 运行
./fileserver
```

### 命令行参数

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `-p` | 端口号 | 8080 | 服务端口 |
| `-r` | 根目录 | 可执行文件下的 files 文件夹 | 文件根目录 |
| `-t` | 标题 | FileServer - 内网文件服务 | 页面标题 |
| `-u` | 用户名 | admin | 管理员用户名 |
| `-w` | 密码 | admin | 管理员密码 |
| `-no-auth` | 禁用认证 | false | 禁用登录认证（仅供测试） |

### 使用示例

```bash
# 使用默认配置启动
./fileserver

# 自定义端口和目录
./fileserver -p 8088 -r /home/user/files

# 自定义管理员账号
./fileserver -u myadmin -w mypassword123

# 禁用认证（仅限内网测试环境使用）
./fileserver -no-auth
```

### 部署注意事项

1. **默认访问地址**: http://localhost:8080
2. **默认管理员**: 用户名 `admin`，密码 `admin`
3. **首次运行**: 系统会自动创建默认管理员账号
4. **文件目录**: 默认在可执行文件所在目录下的 `files` 文件夹

## 目录结构

```
file_servers_go/
├── main.go              # 主程序入口
├── handler/
│   ├── api.go          # API 认证相关（登录、Token 验证）
│   ├── file.go         # 文件操作 API
│   ├── user.go         # 用户管理 API
│   └── log.go          # 日志记录功能
├── utils/
│   └── zip.go          # ZIP 解压工具
├── static/             # 前端静态资源
│   ├── index.html      # 主页面
│   ├── login.html      # 登录页面
│   ├── users.html      # 用户管理页面
│   └── lib/            # 第三方库
└── data/               # 数据存储目录（自动创建）
    ├── users.json      # 用户数据文件
    └── app.log         # 操作日志文件
```

## API 文档

### 认证相关

#### 登录
- **URL**: `/api/login`
- **方法**: POST
- **请求体**:
```json
{
    "username": "admin",
    "password": "admin"
}
```
- **响应**:
```json
{
    "code": 200,
    "message": "登录成功",
    "data": {
        "token": "eyJhbGciOiJIUzI1NiIs...",
        "username": "admin",
        "isAdmin": true
    }
}
```

#### 验证 Token
- **URL**: `/api/verify`
- **方法**: GET
- **请求头**: `Authorization: Bearer <token>`
- **响应**:
```json
{
    "code": 200,
    "message": "Token 有效",
    "data": {
        "username": "admin",
        "isAdmin": true
    }
}
```

#### 前端日志（无需认证）
- **URL**: `/api/log`
- **方法**: POST
- **说明**: 用于前端页面记录用户操作日志
- **请求体**:
```json
{
    "username": "admin",
    "operation": "页面访问",
    "details": "访问目录: documents"
}
```
- **响应**:
```json
{
    "code": 200,
    "message": "success",
    "data": null
}
```

### 文件操作

#### 获取文件列表
- **URL**: `/api/list`
- **方法**: GET
- **参数**: `path` - 目录路径（相对路径，默认为当前目录）
- **请求头**: `Authorization: Bearer <token>`
- **响应**:
```json
{
    "code": 200,
    "message": "success",
    "data": {
        "files": [
            {
                "name": "文件夹",
                "path": "documents",
                "fullPath": "/path/to/files/documents",
                "isDir": true,
                "size": 0,
                "modifiedTime": "2024-01-01T12:00:00Z",
                "extension": "",
                "type": "folder"
            },
            {
                "name": "文件.txt",
                "path": "file.txt",
                "fullPath": "/path/to/files/file.txt",
                "isDir": false,
                "size": 1024,
                "modifiedTime": "2024-01-01T12:00:00Z",
                "extension": ".txt",
                "type": "text"
            }
        ],
        "isReadOnly": false
    }
}
```

#### 上传文件
- **URL**: `/api/upload`
- **方法**: POST
- **表单参数**:
  - `path` - 目标目录路径
  - `file` - 文件内容
- **请求头**: `Authorization: Bearer <token>`
- **响应**:
```json
{
    "code": 200,
    "message": "success",
    "data": {
        "name": "uploaded.txt",
        "path": "/path/to/files/uploaded.txt"
    }
}
```

#### 上传文件夹
- **URL**: `/api/upload-folder`
- **方法**: POST
- **表单参数**:
  - `path` - 目标目录路径
  - `file` - ZIP 文件内容
- **请求头**: `Authorization: Bearer <token>`
- **说明**: 上传 ZIP 文件后会自动解压到目标目录

#### 下载文件
- **URL**: `/api/download`
- **方法**: GET
- **参数**: `path` - 文件路径
- **请求头**: `Authorization: Bearer <token>`
- **响应**: 文件流

#### 创建文件夹
- **URL**: `/api/mkdir`
- **方法**: POST
- **请求体**:
```json
{
    "path": ".",
    "name": "新文件夹"
}
```
- **响应**:
```json
{
    "code": 200,
    "message": "success",
    "data": {
        "path": "/path/to/files/新文件夹"
    }
}
```

#### 重命名文件
- **URL**: `/api/rename`
- **方法**: POST
- **请求体**:
```json
{
    "path": "oldname.txt",
    "newName": "newname.txt"
}
```

#### 删除文件/文件夹
- **URL**: `/api/delete`
- **方法**: POST
- **请求体**:
```json
{
    "path": "file.txt"
}
```

#### 获取文件信息
- **URL**: `/api/info`
- **方法**: GET
- **参数**: `path` - 文件路径
- **响应**:
```json
{
    "code": 200,
    "message": "success",
    "data": {
        "name": "file.txt",
        "path": "/path/to/files/file.txt",
        "isDir": false,
        "size": 1024,
        "modifiedTime": "2024-01-01T12:00:00Z",
        "extension": ".txt",
        "type": "text"
    }
}
```

#### 获取目录树
- **URL**: `/api/dirs-tree`
- **方法**: GET
- **参数**: `path` - 目录路径
- **响应**: 返回目录的树形结构

### 用户管理（仅管理员）

#### 获取用户列表
- **URL**: `/api/users`
- **方法**: GET
- **请求头**: `Authorization: Bearer <token>`（管理员 token）
- **响应**:
```json
{
    "code": 200,
    "message": "success",
    "data": [
        {
            "id": "user_aa01010101",
            "username": "admin",
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
            "isDisabled": false,
            "dirAccess": [
                {"path": "*", "isReadOnly": false}
            ]
        }
    ]
}
```

#### 创建用户
- **URL**: `/api/users/create`
- **方法**: POST
- **请求体**:
```json
{
    "username": "user1",
    "password": "password123",
    "dirAccess": [
        {"path": "documents", "isReadOnly": true}
    ]
}
```

#### 更新用户
- **URL**: `/api/users/update?username=user1`
- **方法**: POST
- **请求体**:
```json
{
    "password": "newpassword",
    "dirAccess": [
        {"path": "documents", "isReadOnly": false}
    ],
    "isDisabled": false
}
```

#### 删除用户
- **URL**: `/api/users/delete?username=user1`
- **方法**: POST

#### 重置用户密码
- **URL**: `/api/users/reset-password`
- **方法**: POST
- **请求体**:
```json
{
    "username": "user1",
    "password": "newpassword"
}
```

### 个人信息

#### 获取当前用户信息
- **URL**: `/api/users/me`
- **方法**: GET
- **请求头**: `Authorization: Bearer <token>`
- **响应**:
```json
{
    "code": 200,
    "message": "success",
    "data": {
        "id": "user_aa01010101",
        "username": "user1",
        "isAdmin": false,
        "isDisabled": false,
        "dirAccess": [
            {"path": "documents", "isReadOnly": true}
        ]
    }
}
```

#### 修改密码
- **URL**: `/api/users/change-password`
- **方法**: POST
- **请求体**:
```json
{
    "oldPassword": "oldpassword",
    "newPassword": "newpassword"
}
```

## 权限配置说明

### dirAccess 配置

在创建或更新用户时，可以通过 `dirAccess` 配置用户的访问权限：

```json
{
    "dirAccess": [
        {"path": "*", "isReadOnly": false},        // 访问所有目录
        {"path": "documents", "isReadOnly": true},  // 只读访问 documents 目录
        {"path": "shared", "isReadOnly": false}    // 读写访问 shared 目录
    ]
}
```

| path 值 | 说明 |
|---------|------|
| `*` | 访问所有目录 |
| `documents` | 只访问 documents 及其子目录 |
| `documents/reports` | 只访问 documents/reports 及其子目录 |

### 权限规则

1. 管理员（admin）默认拥有所有目录的读写权限
2. 普通用户只能访问 `dirAccess` 中配置的目录
3. `isReadOnly: true` 时，用户只能查看和下载文件，无法上传、删除或修改

## 日志记录

### 日志文件位置

所有操作日志保存在 `data/app.log` 文件中。

### 日志格式

```
2024-01-01 12:00:00 - admin - 登录 - 登录成功 - IP: 127.0.0.1:12345
```

格式：`时间 - 用户名 - 操作类型 - 详情 - 客户端IP`

### 记录的操作类型

| 操作类型 | 说明 | 记录内容 |
|----------|------|----------|
| 登录 | 用户登录系统 | 登录成功/失败、客户端IP |
| 退出 | 用户登出系统 | 登出时间 |
| 页面访问 | 访问文件页面 | 访问的目录路径 |
| 下载 | 下载文件 | 文件路径、客户端IP |
| 上传 | 上传文件 | 文件名、上传路径 |
| 创建文件夹 | 新建目录 | 文件夹路径 |
| 重命名 | 文件/文件夹重命名 | 原路径 -> 新路径 |
| 删除 | 删除文件/文件夹 | 被删除的路径 |
| 分享链接 | 生成分享链接 | 被分享的文件路径 |

## 常见问题

### 1. 中文文件名显示乱码？

系统已内置 RFC 5987 编码支持，所有浏览器的下载功能都经过测试，确保中文文件名正常显示。

### 2. 上传文件大小限制？

- 单文件上传：32MB
- 文件夹上传（ZIP）：512MB

如需调整，可修改 `handler/file.go` 中的 `ParseMultipartForm` 参数。

### 3. 如何修改默认端口？

使用 `-p` 参数：
```bash
./fileserver -p 8080
```

### 4. 忘记管理员密码怎么办？

1. 停止服务器
2. 删除 `data/users.json` 文件
3. 重新启动服务器，将自动创建默认管理员账号（admin/admin）

### 5. 支持哪些文件类型图标？

| 类型 | 扩展名 | 图标颜色 |
|------|--------|----------|
| 文件夹 | - | 金色 |
| 图片 | .jpg, .jpeg, .png, .gif, .bmp, .webp | 粉色 |
| 代码 | .go, .js, .ts, .html, .css, .py, .java, .c, .cpp | 绿色 |
| 压缩包 | .zip, .rar, .7z, .tar, .gz | 紫色 |
| 文档 | .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx | 蓝色 |
| 文本 | .txt, .md, .log | 蓝色 |
| 其他 | - | 蓝色 |

### 6. 如何进行外部静态资源自定义？

如果可执行文件同级目录存在 `index.html` 或 `static` 文件夹，系统将优先使用外部静态资源，方便进行界面定制。

## 更新日志

### v1.1.0
- 新增操作日志记录功能（登录、退出、访问、下载、上传、重命名、删除等）
- 新增前端日志记录 API
- 新增文件名搜索功能（支持模糊匹配）
- 优化界面显示，移除视图切换按钮，仅保留列表视图
- 优化文件名显示，超出宽度自动截断

### v1.0.0
- 初始版本发布
- 支持文件浏览、上传、下载
- 支持多用户管理
- 支持权限控制
- 深色/浅色主题切换
- 完整的中文支持

## 许可证

MIT License

## 贡献者

感谢所有为这个项目做出贡献的人！
