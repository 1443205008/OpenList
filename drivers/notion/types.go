package notion

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

type NotionService struct {
	cookie         string
	token          string
	spaceID        string
	databaseID     string
	filePageID     string
	userId         string
	cycleTLSClient *CycleTLSClient
}

type FileInfo struct {
	ID           int       `json:"id"`
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	NotionPageID string    `json:"notion_page_id"`
	URL          string    `json:"url"`
	ContentType  string    `json:"content_type"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Directory struct {
	ID         int       `json:"id" gorm:"primaryKey"`
	Name       string    `json:"name"`
	ParentID   *int      `json:"parent_id"`
	DatabaseID string    `json:"database_id"`
	Deleted    bool      `json:"deleted" gorm:"default:false"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type File struct {
	ID           int       `json:"id" gorm:"primaryKey"`
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	NotionPageID string    `json:"notion_page_id"`
	DirectoryID  int       `json:"directory_id"`
	IsChunked    bool      `json:"is_chunked" gorm:"default:false"`
	ChunkSize    int64     `json:"chunk_size" gorm:"default:0"`
	Deleted      bool      `json:"deleted" gorm:"default:false"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// FileChunk 存储文件分块信息
type FileChunk struct {
	ID           int       `json:"id" gorm:"primaryKey"`
	FileID       int       `json:"file_id"`
	ChunkIndex   int       `json:"chunk_index"`
	ChunkSize    int64     `json:"chunk_size"`
	StartOffset  int64     `json:"start_offset"`
	EndOffset    int64     `json:"end_offset"`
	NotionPageID string    `json:"notion_page_id"`
	Deleted      bool      `json:"deleted" gorm:"default:false"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type NotionFile struct {
	URL        string `json:"url"`
	ExpiryTime string `json:"expiry_time"`
}

type PropertyResponse struct {
	Object string       `json:"object"`
	Type   string       `json:"type"`
	Files  []FileObject `json:"files"`
}

type FileObject struct {
	Type string     `json:"type"`
	Name string     `json:"name"`
	File NotionFile `json:"file"`
}

type UploadFileRequest struct {
	Bucket              string     `json:"bucket"`
	Name                string     `json:"name"`
	ContentType         string     `json:"contentType"`
	Record              RecordInfo `json:"record"`
	SupportExtraHeaders bool       `json:"supportExtraHeaders"`
	ContentLength       int64      `json:"contentLength"`
}

type RecordInfo struct {
	Table   string `json:"table"`
	ID      string `json:"id"`
	SpaceID string `json:"spaceId"`
}

type UploadResponse struct {
	Type                string       `json:"type"`
	URL                 string       `json:"url"`
	SignedGetUrl        string       `json:"signedGetUrl"`
	SignedUploadPostUrl string       `json:"signedUploadPostUrl"`
	SignedPutUrl        string       `json:"signedPutUrl"`
	PostHeaders         []string     `json:"postHeaders"`
	PutHeaders          []putHeader  `json:"putHeaders"`
	Fields              UploadFields `json:"fields"`
}

type putHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type UploadFields struct {
	ContentType       string `json:"Content-Type"`
	XAmzStorageClass  string `json:"x-amz-storage-class"`
	Tagging           string `json:"tagging"`
	Bucket            string `json:"bucket"`
	XAmzAlgorithm     string `json:"X-Amz-Algorithm"`
	XAmzCredential    string `json:"X-Amz-Credential"`
	XAmzDate          string `json:"X-Amz-Date"`
	XAmzSecurityToken string `json:"X-Amz-Security-Token"`
	Key               string `json:"key"`
	Policy            string `json:"Policy"`
	XAmzSignature     string `json:"X-Amz-Signature"`
}

type UpdateFileStatusRequest struct {
	RequestID    string        `json:"requestId"`
	Transactions []Transaction `json:"transactions"`
}

type Transaction struct {
	ID      string      `json:"id"`
	SpaceID string      `json:"spaceId"`
	Debug   DebugInfo   `json:"debug"`
	Ops     []Operation `json:"operations"`
}

type DebugInfo struct {
	UserAction string `json:"userAction"`
}

type Operation struct {
	Pointer Pointer     `json:"pointer"`
	Path    []string    `json:"path"`
	Command string      `json:"command"`
	Args    interface{} `json:"args"`
}

type Pointer struct {
	ID      string `json:"id"`
	Table   string `json:"table"`
	SpaceID string `json:"spaceId"`
}

type CreatePageRequest struct {
	Parent     Parent     `json:"parent"`
	Properties Properties `json:"properties"`
}

type Parent struct {
	DatabaseID string `json:"database_id"`
}

type Properties struct {
	Title TitleProperty `json:"Title"`
}

type TitleProperty struct {
	Title []TitleText `json:"title"`
}

type RichTextProperty struct {
	RichText []RichText `json:"rich_text"`
}

type TitleText struct {
	Text TextContent `json:"text"`
}

type RichText struct {
	Text TextContent `json:"text"`
}

type TextContent struct {
	Content string `json:"content"`
}

type CreatePageResponse struct {
	ID         string     `json:"id"`
	Parent     Parent     `json:"parent"`
	Properties Properties `json:"properties"`
}

// ChunkFileStream 实现model.FileStreamer接口，用于分块上传
type ChunkFileStream struct {
	io.Reader
	name     string
	size     int64
	mimetype string
	utils.Closers
}

func (c *ChunkFileStream) GetName() string {
	return c.name
}

func (c *ChunkFileStream) GetSize() int64 {
	return c.size
}

func (c *ChunkFileStream) GetMimetype() string {
	return c.mimetype
}

func (c *ChunkFileStream) Close() error {
	if closer, ok := c.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (c *ChunkFileStream) GetID() string {
	return ""
}

func (c *ChunkFileStream) GetPath() string {
	return ""
}

func (c *ChunkFileStream) ModTime() time.Time {
	return time.Now()
}

func (c *ChunkFileStream) CreateTime() time.Time {
	return time.Now()
}

func (c *ChunkFileStream) GetHash() utils.HashInfo {
	return utils.HashInfo{}
}

func (c *ChunkFileStream) IsDir() bool {
	return false
}

func (c *ChunkFileStream) NeedStore() bool {
	return false
}

func (c *ChunkFileStream) IsForceStreamUpload() bool {
	return false
}

func (c *ChunkFileStream) GetExist() model.Obj {
	return nil
}

func (c *ChunkFileStream) SetExist(model.Obj) {
}

func (c *ChunkFileStream) RangeRead(httpRange http_range.Range) (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ChunkFileStream) CacheFullInTempFile() (model.File, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ChunkFileStream) SetTmpFile(*os.File) {
}

func (c *ChunkFileStream) GetFile() model.File {
	return nil
}

// ChunkedRangeReadCloser 处理分块文件的Range请求
type ChunkedRangeReadCloser struct {
	notionClient *NotionService
	chunks       []FileChunk
	fileSize     int64
	utils.Closers
}

func NewChunkedRangeReadCloser(notionClient *NotionService, chunks []FileChunk, fileSize int64) *ChunkedRangeReadCloser {
	return &ChunkedRangeReadCloser{
		notionClient: notionClient,
		chunks:       chunks,
		fileSize:     fileSize,
		Closers:      utils.NewClosers(),
	}
}

func (c *ChunkedRangeReadCloser) RangeRead(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
	// 边界检查
	if httpRange.Start < 0 {
		return nil, fmt.Errorf("invalid range start: %d", httpRange.Start)
	}
	if httpRange.Start >= c.fileSize {
		return nil, fmt.Errorf("range start %d exceeds file size %d", httpRange.Start, c.fileSize)
	}

	if httpRange.Length == -1 {
		httpRange.Length = c.fileSize - httpRange.Start
	}

	// 确保请求范围不超过文件大小
	requestEnd := httpRange.Start + httpRange.Length
	if requestEnd > c.fileSize {
		httpRange.Length = c.fileSize - httpRange.Start
		requestEnd = c.fileSize
	}

	// 找到需要的分块
	var neededChunks []FileChunk
	for _, chunk := range c.chunks {
		// 检查分块是否与请求范围重叠
		if chunk.StartOffset < requestEnd && chunk.EndOffset > httpRange.Start {
			neededChunks = append(neededChunks, chunk)
		}
	}

	if len(neededChunks) == 0 {
		return nil, fmt.Errorf("no chunks found for range %d-%d (file size: %d, total chunks: %d)",
			httpRange.Start, requestEnd-1, c.fileSize, len(c.chunks))
	}

	return &ChunkedReader{
		notionClient: c.notionClient,
		chunks:       neededChunks,
		requestStart: httpRange.Start,
		requestEnd:   requestEnd,
		currentChunk: 0,
	}, nil
}

// ChunkedReader 实现跨分块的流式读取
type ChunkedReader struct {
	notionClient  *NotionService
	chunks        []FileChunk
	requestStart  int64
	requestEnd    int64
	currentChunk  int
	currentReader io.ReadCloser
	currentOffset int64
	totalRead     int64
}

func (r *ChunkedReader) Read(p []byte) (n int, err error) {
	if r.totalRead >= r.requestEnd-r.requestStart {
		return 0, io.EOF
	}

	// 如果当前没有reader或者当前reader已读完，切换到下一个分块
	if r.currentReader == nil {
		if r.currentChunk >= len(r.chunks) {
			return 0, io.EOF
		}

		chunk := r.chunks[r.currentChunk]

		// 计算在当前分块中的读取范围
		chunkStart := max(r.requestStart, chunk.StartOffset) - chunk.StartOffset
		chunkEnd := min(r.requestEnd, chunk.EndOffset) - chunk.StartOffset

		// 重试逻辑：最多重试3次
		var reader io.ReadCloser
		maxRetries := 3
		for retry := 0; retry < maxRetries; retry++ {
			// 获取分块的下载链接
			property, err := r.notionClient.GetPageProperty(chunk.NotionPageID, r.notionClient.filePageID)
			if err != nil {
				if retry == maxRetries-1 {
					return 0, fmt.Errorf("获取分块%d下载链接失败(重试%d次): %v", r.currentChunk, retry+1, err)
				}
				time.Sleep(time.Second * time.Duration(retry+1)) // 递增延迟
				continue
			}

			if len(property.Files) == 0 {
				return 0, fmt.Errorf("分块%d没有文件", r.currentChunk)
			}

			// 创建HTTP请求获取分块数据
			reader, err = r.createChunkReader(property.Files[0].File.URL, chunkStart, chunkEnd-chunkStart)
			if err != nil {
				if retry == maxRetries-1 {
					return 0, fmt.Errorf("创建分块%d读取器失败(重试%d次): %v", r.currentChunk, retry+1, err)
				}
				time.Sleep(time.Second * time.Duration(retry+1)) // 递增延迟
				continue
			}

			// 成功创建reader，跳出重试循环
			break
		}

		r.currentReader = reader
		r.currentOffset = chunkStart
	}

	// 从当前reader读取数据
	remainingBytes := r.requestEnd - r.requestStart - r.totalRead
	if int64(len(p)) > remainingBytes {
		p = p[:remainingBytes]
	}

	n, err = r.currentReader.Read(p)
	r.totalRead += int64(n)

	// 处理读取错误和EOF
	if err != nil {
		if err == io.EOF {
			r.currentReader.Close()
			r.currentReader = nil
			r.currentChunk++

			// 如果还有更多数据要读取，继续下一个分块
			if r.totalRead < r.requestEnd-r.requestStart && r.currentChunk < len(r.chunks) {
				err = nil
			}
		} else {
			// 非EOF错误，关闭当前reader，下次读取时会重新创建
			r.currentReader.Close()
			r.currentReader = nil
		}
	}

	return n, err
}

func (r *ChunkedReader) Close() error {
	if r.currentReader != nil {
		return r.currentReader.Close()
	}
	return nil
}

func (r *ChunkedReader) createChunkReader(url string, offset, length int64) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %v", err)
	}

	// 设置Range头
	if length > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	} else {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	// 设置User-Agent和其他必要的头部
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")

	// 创建带超时的HTTP客户端，适合大文件下载
	client := &http.Client{
		Timeout: time.Minute * 30, // 30分钟超时，适合大文件分块下载
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送HTTP请求失败: %v", err)
	}

	// 检查状态码，206是部分内容，200是完整内容
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP请求失败，状态码: %d, URL: %s", resp.StatusCode, url)
	}

	return resp.Body, nil
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// StreamChunkUploader 流式分块上传器
type StreamChunkUploader struct {
	file         model.FileStreamer
	fileSize     int64
	chunkSize    int64
	chunkCount   int64
	fileName     string
	notionClient *NotionService
	fileRecord   *File
	db           interface{} // 使用 interface{} 避免导入 gorm
	ctx          context.Context
	progress     func(float64)
}

// Upload 执行流式分块上传
func (s *StreamChunkUploader) Upload() ([]FileChunk, error) {
	var chunks []FileChunk
	var totalRead int64
	var createdPageIDs []string // 跟踪已创建的页面ID，用于错误清理

	for i := int64(0); i < s.chunkCount; i++ {
		// 检查上下文是否被取消
		select {
		case <-s.ctx.Done():
			// 上下文取消时，清理已创建的页面
			s.cleanupCreatedPages(createdPageIDs)
			return nil, s.ctx.Err()
		default:
		}

		// 计算当前分块的大小
		currentChunkSize := s.chunkSize
		if totalRead+currentChunkSize > s.fileSize {
			currentChunkSize = s.fileSize - totalRead
		}

		// 创建分块页面
		chunkName := fmt.Sprintf("%s.chunk%d", s.fileName, i)
		pageID, err := s.notionClient.CreateDatabasePage(chunkName)
		if err != nil {
			// 创建页面失败，清理已创建的页面
			s.cleanupCreatedPages(createdPageIDs)
			return nil, fmt.Errorf("创建分块页面失败: %v", err)
		}
		createdPageIDs = append(createdPageIDs, pageID)

		// 创建限制读取器，只读取当前分块的数据
		chunkReader := io.LimitReader(s.file, currentChunkSize)

		// 上传分块并计算进度
		chunkProgress := func(percentage float64) {
			totalProgress := (float64(i) + percentage/100.0) / float64(s.chunkCount) * 100.0
			if s.progress != nil {
				s.progress(totalProgress)
			}
		}

		// 使用专门的分块上传方法，避免缓存，增加重试机制
		err = s.uploadChunkWithRetry(chunkReader, currentChunkSize, chunkName, pageID, chunkProgress, 3)
		if err != nil {
			// 上传失败，清理已创建的页面
			s.cleanupCreatedPages(createdPageIDs)
			return nil, fmt.Errorf("上传分块%d失败: %v", i, err)
		}

		// 创建分块记录
		chunk := FileChunk{
			FileID:       s.fileRecord.ID,
			ChunkIndex:   int(i),
			ChunkSize:    currentChunkSize,
			StartOffset:  totalRead,
			EndOffset:    totalRead + currentChunkSize,
			NotionPageID: pageID,
		}
		chunks = append(chunks, chunk)

		totalRead += currentChunkSize
	}

	return chunks, nil
}

// uploadChunkWithRetry 带重试机制的分块上传
func (s *StreamChunkUploader) uploadChunkWithRetry(reader io.Reader, size int64, name, pageID string, progress func(float64), maxRetries int) error {
	var lastErr error
	for retry := 0; retry < maxRetries; retry++ {
		// 对于重试，需要重新创建reader（如果可能的话）
		err := s.notionClient.UploadAndUpdateChunkPut(reader, size, name, pageID, progress)
		if err == nil {
			return nil
		}

		lastErr = err
		if retry < maxRetries-1 {
			// 等待后重试，递增延迟
			time.Sleep(time.Second * time.Duration(retry+1))
		}
	}

	return fmt.Errorf("经过%d次重试后仍然失败: %v", maxRetries, lastErr)
}

// cleanupCreatedPages 清理已创建的Notion页面（这里只是记录，实际删除可能需要额外的API调用）
func (s *StreamChunkUploader) cleanupCreatedPages(pageIDs []string) {
	// 注意：Notion API删除页面比较复杂，这里只是记录警告
	// 在生产环境中，可能需要实现具体的页面删除逻辑
	if len(pageIDs) > 0 {
		fmt.Printf("警告：分块上传失败，需要清理%d个已创建的Notion页面\n", len(pageIDs))
		for _, pageID := range pageIDs {
			fmt.Printf("  页面ID: %s\n", pageID)
		}
	}
}
