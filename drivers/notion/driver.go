package notion

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

const (
	// MaxChunkSize Notion单个文件最大支持5GB，我们设置为4.5GB留出余量
	MaxChunkSize = 4.5 * 1024 * 1024 * 1024 // 4.5GB
	// ChunkThreshold 超过5GB的文件启用分块
	ChunkThreshold = 5 * 1024 * 1024 * 1024 // 5GB
	// MaxConcurrentUploads 最大并发上传数，避免过多连接
	MaxConcurrentUploads = 10
	// MaxConcurrentChunks 最大并发分块数
	MaxConcurrentChunks = 2
)

type Notion struct {
	model.Storage
	Addition
	db           *gorm.DB
	notionClient *NotionService
}

func (d *Notion) Config() driver.Config {
	return config
}

func (d *Notion) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Notion) Init(ctx context.Context) error {
	// 初始化数据库连接
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		d.DBUser, d.DBPass, d.DBHost, d.DBPort, d.DBName)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("连接数据库失败: %v", err)
	}

	// 自动迁移数据库表
	err = db.AutoMigrate(&Directory{}, &File{}, &FileChunk{})
	if err != nil {
		return fmt.Errorf("迁移数据库失败: %v", err)
	}

	// 检查是否存在根目录，如果不存在则创建
	var rootDir Directory
	if err := db.Where("parent_id IS NULL AND database_id = ?", d.NotionDatabaseID).First(&rootDir).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// 创建根目录
			rootDir = Directory{
				Name:       "/",
				ParentID:   nil,
				DatabaseID: d.NotionDatabaseID,
				Deleted:    false,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}
			if err := db.Create(&rootDir).Error; err != nil {
				return fmt.Errorf("创建根目录失败: %v", err)
			}
		} else {
			return fmt.Errorf("检查根目录失败: %v", err)
		}
	}

	// 初始化Notion客户端
	d.notionClient = NewNotionService(d.NotionCookie, d.NotionToken, d.NotionSpaceID, d.NotionDatabaseID, d.NotionFilePageID)
	d.db = db

	return nil
}

func (d *Notion) Drop(ctx context.Context) error {
	return nil
}

func (d *Notion) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	var objs []model.Obj
	dirID := 1
	if dir != nil {
		id, _ := strconv.Atoi(dir.GetID())
		dirID = id
	}

	// 获取目录列表
	var directories []Directory
	if err := d.db.Where("parent_id = ? AND database_id = ? AND deleted = ?", dirID, d.NotionDatabaseID, false).Find(&directories).Error; err != nil {
		return nil, fmt.Errorf("获取目录列表失败: %v", err)
	}

	for _, dir := range directories {
		objs = append(objs, &model.Object{
			ID:       strconv.Itoa(dir.ID),
			Name:     dir.Name,
			Size:     0,
			Modified: dir.UpdatedAt,
			IsFolder: true,
		})
	}

	// 获取文件列表
	var files []File
	if err := d.db.Where("directory_id = ? AND deleted = ?", dirID, false).Find(&files).Error; err != nil {
		return nil, fmt.Errorf("获取文件列表失败: %v", err)
	}

	for _, file := range files {
		objs = append(objs, &model.Object{
			ID:       strconv.Itoa(file.ID),
			Name:     file.Name,
			Size:     file.Size,
			Modified: file.UpdatedAt,
			IsFolder: false,
		})
	}

	return objs, nil
}

func (d *Notion) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	var f File
	if err := d.db.Where("id = ? AND deleted = ?", file.GetID(), false).First(&f).Error; err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %v", err)
	}

	// 检查是否为分块文件
	if f.IsChunked {
		// 获取所有分块信息
		var chunks []FileChunk
		if err := d.db.Where("file_id = ? AND deleted = ?", f.ID, false).Order("chunk_index").Find(&chunks).Error; err != nil {
			return nil, fmt.Errorf("获取文件分块信息失败: %v", err)
		}

		if len(chunks) == 0 {
			return nil, fmt.Errorf("分块文件没有找到分块数据")
		}

		// 创建分块Range读取器
		rangeReadCloser := NewChunkedRangeReadCloser(d.notionClient, chunks, f.Size)

		resultRangeReader := func(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
			return rangeReadCloser.RangeRead(ctx, httpRange)
		}

		// resultRangeReadCloser := &model.RangeReadCloser{RangeReader: resultRangeReader}

		return &model.Link{
			RangeReader: stream.RateLimitRangeReaderFunc(resultRangeReader),
		}, nil
	} else {
		// 单文件，返回直接URL
		property, err := d.notionClient.GetPageProperty(f.NotionPageID, d.NotionFilePageID)
		if err != nil {
			return nil, fmt.Errorf("获取文件URL失败: %v", err)
		}

		return &model.Link{
			URL: property.Files[0].File.URL,
		}, nil
	}
}

func (d *Notion) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) (model.Obj, error) {
	parentID := 1
	if parentDir != nil {
		id, _ := strconv.Atoi(parentDir.GetID())
		parentID = id
	}
	//先检查是否存在同名目录
	var existingDir Directory
	if err := d.db.Where("parent_id = ? AND name = ? AND deleted = ?", parentID, dirName, false).First(&existingDir).Error; err == nil {
		// 如果找到同名目录，直接返回该目录信息
		return &model.Object{
			ID:       strconv.Itoa(existingDir.ID),
			Name:     existingDir.Name,
			Size:     0,
			Modified: existingDir.UpdatedAt,
			IsFolder: true,
		}, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		// 如果是其他错误,返回错误信息
		return nil, fmt.Errorf("检查目录是否存在时发生错误: %v", err)
	}

	dir := &Directory{
		Name:       dirName,
		ParentID:   &parentID,
		DatabaseID: d.NotionDatabaseID,
	}
	if err := d.db.Create(dir).Error; err != nil {
		return nil, fmt.Errorf("创建目录失败: %v", err)
	}

	return &model.Object{
		ID:       strconv.Itoa(dir.ID),
		Name:     dir.Name,
		Size:     0,
		Modified: dir.UpdatedAt,
		IsFolder: true,
	}, nil
}

func (d *Notion) Move(ctx context.Context, srcObj, dstDir model.Obj) (model.Obj, error) {
	if srcObj.IsDir() {
		var dir Directory
		if err := d.db.Where("id = ? AND deleted = ?", srcObj.GetID(), false).First(&dir).Error; err != nil {
			return nil, fmt.Errorf("获取目录信息失败: %v", err)
		}

		parentID, _ := strconv.Atoi(dstDir.GetID())
		dir.ParentID = &parentID
		if err := d.db.Save(&dir).Error; err != nil {
			return nil, fmt.Errorf("移动目录失败: %v", err)
		}

		return &model.Object{
			ID:       strconv.Itoa(dir.ID),
			Name:     dir.Name,
			Size:     0,
			Modified: dir.UpdatedAt,
			IsFolder: true,
		}, nil
	} else {
		var file File
		if err := d.db.Where("id = ? AND deleted = ?", srcObj.GetID(), false).First(&file).Error; err != nil {
			return nil, fmt.Errorf("获取文件信息失败: %v", err)
		}

		dirID, _ := strconv.Atoi(dstDir.GetID())
		file.DirectoryID = dirID
		if err := d.db.Save(&file).Error; err != nil {
			return nil, fmt.Errorf("移动文件失败: %v", err)
		}

		return &model.Object{
			ID:       strconv.Itoa(file.ID),
			Name:     file.Name,
			Size:     file.Size,
			Modified: file.UpdatedAt,
			IsFolder: false,
		}, nil
	}
}

func (d *Notion) Rename(ctx context.Context, srcObj model.Obj, newName string) (model.Obj, error) {
	if srcObj.IsDir() {
		var dir Directory
		if err := d.db.Where("id = ? AND deleted = ?", srcObj.GetID(), false).First(&dir).Error; err != nil {
			return nil, fmt.Errorf("获取目录信息失败: %v", err)
		}

		dir.Name = newName
		if err := d.db.Save(&dir).Error; err != nil {
			return nil, fmt.Errorf("重命名目录失败: %v", err)
		}

		return &model.Object{
			ID:       strconv.Itoa(dir.ID),
			Name:     dir.Name,
			Size:     0,
			Modified: dir.UpdatedAt,
			IsFolder: true,
		}, nil
	} else {
		var file File
		if err := d.db.Where("id = ? AND deleted = ?", srcObj.GetID(), false).First(&file).Error; err != nil {
			return nil, fmt.Errorf("获取文件信息失败: %v", err)
		}

		file.Name = newName
		if err := d.db.Save(&file).Error; err != nil {
			return nil, fmt.Errorf("重命名文件失败: %v", err)
		}

		return &model.Object{
			ID:       strconv.Itoa(file.ID),
			Name:     file.Name,
			Size:     file.Size,
			Modified: file.UpdatedAt,
			IsFolder: false,
		}, nil
	}
}

func (d *Notion) Copy(ctx context.Context, srcObj, dstDir model.Obj) (model.Obj, error) {
	if srcObj.IsDir() {
		// 复制目录
		var srcDir Directory
		if err := d.db.Where("id = ? AND deleted = ?", srcObj.GetID(), false).First(&srcDir).Error; err != nil {
			return nil, fmt.Errorf("获取源目录信息失败: %v", err)
		}

		// 创建新目录
		dstDirID, _ := strconv.Atoi(dstDir.GetID())
		newDir := &Directory{
			Name:       srcDir.Name,
			ParentID:   &dstDirID,
			DatabaseID: d.NotionDatabaseID,
		}
		if err := d.db.Create(newDir).Error; err != nil {
			return nil, fmt.Errorf("创建目标目录失败: %v", err)
		}

		// 复制目录下的所有文件
		var files []File
		if err := d.db.Where("directory_id = ? AND deleted = ?", srcDir.ID, false).Find(&files).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("获取源目录文件列表失败: %v", err)
		}

		for _, file := range files {
			newFile := &File{
				Name:         file.Name,
				Size:         file.Size,
				SHA1:         file.SHA1,
				NotionPageID: file.NotionPageID,
				DirectoryID:  newDir.ID,
			}
			if err := d.db.Create(newFile).Error; err != nil {
				return nil, fmt.Errorf("复制文件失败: %v", err)
			}
		}

		// 递归复制子目录
		var subDirs []Directory
		if err := d.db.Where("parent_id = ? AND deleted = ?", srcDir.ID, false).Find(&subDirs).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("获取子目录列表失败: %v", err)
		}

		// 递归复制子目录
		for _, subDir := range subDirs {
			// 创建子目录对象
			subDirObj := &model.Object{
				ID:       strconv.Itoa(subDir.ID),
				Name:     subDir.Name,
				Size:     0,
				Modified: subDir.UpdatedAt,
				IsFolder: true,
			}
			// 递归复制子目录
			if _, err := d.Copy(ctx, subDirObj, &model.Object{
				ID:       strconv.Itoa(newDir.ID),
				Name:     newDir.Name,
				Size:     0,
				Modified: newDir.UpdatedAt,
				IsFolder: true,
			}); err != nil {
				return nil, fmt.Errorf("复制子目录 %s 失败: %v", subDir.Name, err)
			}
		}

		return &model.Object{
			ID:       strconv.Itoa(newDir.ID),
			Name:     newDir.Name,
			Size:     0,
			Modified: newDir.UpdatedAt,
			IsFolder: true,
		}, nil
	} else {
		// 复制文件
		var srcFile File
		if err := d.db.Where("id = ? AND deleted = ?", srcObj.GetID(), false).First(&srcFile).Error; err != nil {
			return nil, fmt.Errorf("获取源文件信息失败: %v", err)
		}

		// 创建新文件记录
		dstDirID, _ := strconv.Atoi(dstDir.GetID())
		newFile := &File{
			Name:         srcFile.Name,
			Size:         srcFile.Size,
			SHA1:         srcFile.SHA1,
			NotionPageID: srcFile.NotionPageID,
			DirectoryID:  dstDirID,
		}
		if err := d.db.Create(newFile).Error; err != nil {
			return nil, fmt.Errorf("复制文件记录失败: %v", err)
		}

		return &model.Object{
			ID:       strconv.Itoa(newFile.ID),
			Name:     newFile.Name,
			Size:     newFile.Size,
			Modified: newFile.UpdatedAt,
			IsFolder: false,
		}, nil
	}
}

func (d *Notion) Remove(ctx context.Context, obj model.Obj) error {
	if obj.IsDir() {
		if err := d.db.Model(&Directory{}).Where("id = ?", obj.GetID()).Update("deleted", true).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("删除目录失败: %v", err)
		}
		// 删除目录下的所有文件
		if err := d.db.Model(&File{}).Where("directory_id = ?", obj.GetID()).Update("deleted", true).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("删除目录下的文件失败: %v", err)
		}

		// 递归删除子目录及其文件
		var subDirs []Directory
		if err := d.db.Where("parent_id = ? AND deleted = ?", obj.GetID(), false).Find(&subDirs).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("获取子目录失败: %v", err)
		}

		for _, subDir := range subDirs {
			subObj := &model.Object{
				ID:       strconv.Itoa(subDir.ID),
				Name:     subDir.Name,
				IsFolder: true,
			}
			if err := d.Remove(ctx, subObj); err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("删除子目录 %s 失败: %v", subDir.Name, err)
			}
		}
	} else {
		if err := d.db.Model(&File{}).Where("id = ?", obj.GetID()).Update("deleted", true).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("删除文件失败: %v", err)
		}
	}
	return nil
}

func (d *Notion) Put(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress) (model.Obj, error) {
	// 检查是否存在同名文件
	var existingFile File
	if err := d.db.Where("name = ? AND directory_id = ? AND deleted = ?", filepath.Base(file.GetName()), dstDir.GetID(), false).First(&existingFile).Error; err == nil {
		return &model.Object{
			ID:       strconv.Itoa(existingFile.ID),
			Name:     existingFile.Name,
			Size:     existingFile.Size,
			Modified: existingFile.UpdatedAt,
			IsFolder: false,
		}, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("检查文件是否存在时发生错误: %v", err)
	}

	fileSize := file.GetSize()
	fileName := filepath.Base(file.GetName())
	dirID, _ := strconv.Atoi(dstDir.GetID())

	// 判断是否需要分块上传
	if fileSize > ChunkThreshold {
		return d.putChunkedFile(ctx, fileName, fileSize, dirID, file, up)
	} else {
		return d.putSingleFile(ctx, fileName, fileSize, dirID, file, up)
	}
}

// putSingleFile 上传单个文件（小于5GB）
func (d *Notion) putSingleFile(ctx context.Context, fileName string, fileSize int64, dirID int, file model.FileStreamer, up driver.UpdateProgress) (model.Obj, error) {
	// 创建Notion页面
	pageID, err := d.notionClient.CreateDatabasePage(fileName)
	if err != nil {
		return nil, fmt.Errorf("创建Notion页面失败: %v", err)
	}

	// 上传文件到Notion
	hash1, err := d.notionClient.UploadAndUpdateFilePut(file, pageID, up)
	if err != nil {
		return nil, fmt.Errorf("上传文件到Notion失败: %v", err)
	}

	// 保存到数据库
	f := &File{
		Name:         fileName,
		Size:         fileSize,
		SHA1:         hash1,
		NotionPageID: pageID,
		DirectoryID:  dirID,
		IsChunked:    false,
		ChunkSize:    0,
	}
	if err := d.db.Create(f).Error; err != nil {
		return nil, fmt.Errorf("保存文件信息失败: %v", err)
	}

	return &model.Object{
		ID:       strconv.Itoa(f.ID),
		Name:     f.Name,
		Size:     f.Size,
		Modified: f.UpdatedAt,
		IsFolder: false,
	}, nil
}

// putChunkedFile 上传分块文件（大于5GB）- 流式分块上传
func (d *Notion) putChunkedFile(ctx context.Context, fileName string, fileSize int64, dirID int, file model.FileStreamer, up driver.UpdateProgress) (model.Obj, error) {
	// 计算分块数量
	chunkCount := (fileSize + MaxChunkSize - 1) / MaxChunkSize

	// 创建主文件记录
	f := &File{
		Name:        fileName,
		Size:        fileSize,
		DirectoryID: dirID,
		IsChunked:   true,
		ChunkSize:   MaxChunkSize,
	}
	if err := d.db.Create(f).Error; err != nil {
		return nil, fmt.Errorf("创建文件记录失败: %v", err)
	}

	// 创建流式分块上传器
	streamUploader := &StreamChunkUploader{
		file:             file,
		fileSize:         fileSize,
		chunkSize:        MaxChunkSize,
		chunkCount:       chunkCount,
		fileName:         fileName,
		notionClient:     d.notionClient,
		fileRecord:       f,
		db:               d.db,
		ctx:              ctx,
		progress:         up,
		maxConcurrency:   MaxConcurrentChunks,
		progressThrottle: 200 * time.Millisecond,
	}

	// 执行流式分块上传
	chunks, err := streamUploader.Upload()
	if err != nil {
		return nil, fmt.Errorf("流式分块上传失败: %v", err)
	}

	// 批量保存分块记录
	if err := d.db.Create(&chunks).Error; err != nil {
		return nil, fmt.Errorf("保存分块记录失败: %v", err)
	}

	return &model.Object{
		ID:       strconv.Itoa(f.ID),
		Name:     f.Name,
		Size:     f.Size,
		Modified: f.UpdatedAt,
		IsFolder: false,
	}, nil
}

func (d *Notion) GetArchiveMeta(ctx context.Context, obj model.Obj, args model.ArchiveArgs) (model.ArchiveMeta, error) {
	return nil, errs.NotImplement
}

func (d *Notion) ListArchive(ctx context.Context, obj model.Obj, args model.ArchiveInnerArgs) ([]model.Obj, error) {
	return nil, errs.NotImplement
}

func (d *Notion) Extract(ctx context.Context, obj model.Obj, args model.ArchiveInnerArgs) (*model.Link, error) {
	return nil, errs.NotImplement
}

func (d *Notion) ArchiveDecompress(ctx context.Context, srcObj, dstDir model.Obj, args model.ArchiveDecompressArgs) ([]model.Obj, error) {
	return nil, errs.NotImplement
}

var _ driver.Driver = (*Notion)(nil)
