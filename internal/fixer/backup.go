package fixer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Backup creates a backup of a file before modification.
func Backup(originalPath string) (backupPath string, err error) {
	// Generate backup path with timestamp
	ext := filepath.Ext(originalPath)
	base := originalPath[:len(originalPath)-len(ext)]
	timestamp := time.Now().Format("20060102-150405")
	backupPath = fmt.Sprintf("%s.sherlock-backup-%s%s", base, timestamp, ext)

	src, err := os.Open(originalPath)
	if err != nil {
		return "", fmt.Errorf("failed to open original file for backup: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to copy file for backup: %w", err)
	}

	return backupPath, nil
}

// Rollback restores a file from its backup.
func Rollback(originalPath, backupPath string) error {
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	src, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(originalPath)
	if err != nil {
		return fmt.Errorf("failed to create original file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	return nil
}

// CleanupBackups removes old backup files (older than specified duration).
func CleanupBackups(backupDir string, maxAge time.Duration) error {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sherlock-backup" {
			info, err := entry.Info()
			if err == nil && info.ModTime().Before(cutoff) {
				os.Remove(filepath.Join(backupDir, entry.Name()))
			}
		}
	}

	return nil
}
