package utils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// UnzipFolder 解压 ZIP 文件到目标目录，保持文件夹层次结构
func UnzipFolder(zipPath, destDir string) error {
	// 打开 ZIP 文件
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("打开 ZIP 文件失败: %w", err)
	}
	defer reader.Close()

	// 确保目标目录存在
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %w", err)
	}

	// 遍历 ZIP 中的所有文件
	for _, file := range reader.File {
		// 解压文件路径
		filePath := filepath.Join(destDir, file.Name)

		// 检查 ZIP 注入漏洞：防止路径遍历攻击
		if !strings.HasPrefix(filePath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("ZIP 文件包含非法路径: %s", file.Name)
		}

		// 如果是目录，创建它
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, 0755); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}
			continue
		}

		// 创建父目录
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return fmt.Errorf("创建父目录失败: %w", err)
		}

		// 创建目标文件
		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return fmt.Errorf("创建文件失败: %w", err)
		}

		// 打开 ZIP 中的源文件
		srcFile, err := file.Open()
		if err != nil {
			dstFile.Close()
			return fmt.Errorf("打开源文件失败: %w", err)
		}

		// 复制内容
		_, err = io.Copy(dstFile, srcFile)
		srcFile.Close()
		dstFile.Close()

		if err != nil {
			return fmt.Errorf("复制文件内容失败: %w", err)
		}
	}

	return nil
}

// CreateZip 创建 ZIP 文件
func CreateZip(sourceDir, zipPath string) error {
	// 创建 ZIP 文件
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("创建 ZIP 文件失败: %w", err)
	}
	defer zipFile.Close()

	// 创建 ZIP 写入器
	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	// 获取源目录的绝对路径
	absSource, err := filepath.Abs(sourceDir)
	if err != nil {
		return fmt.Errorf("获取源目录路径失败: %w", err)
	}

	// 遍历源目录
	return filepath.Walk(absSource, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 计算相对路径
		relPath, err := filepath.Rel(absSource, path)
		if err != nil {
			return err
		}

		// 跳过根目录本身
		if relPath == "." {
			return nil
		}

		// 创建文件头
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("创建文件头失败: %w", err)
		}
		header.Name = relPath

		// 设置压缩方法
		if info.IsDir() {
			header.Method = zip.Store
		} else {
			header.Method = zip.Deflate
		}

		// 写入文件头
		w, err := writer.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("写入文件头失败: %w", err)
		}

		// 如果是目录，直接返回
		if info.IsDir() {
			return nil
		}

		// 打开源文件
		srcFile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("打开源文件失败: %w", err)
		}
		defer srcFile.Close()

		// 复制内容
		_, err = io.Copy(w, srcFile)
		if err != nil {
			return fmt.Errorf("复制文件内容失败: %w", err)
		}

		return nil
	})
}
