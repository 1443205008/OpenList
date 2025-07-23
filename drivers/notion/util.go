package notion

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/google/uuid"
)

const (
	NotionAPIBaseURL = "https://www.notion.so/api/v3"
	S3BaseURL        = "https://prod-files-secure.s3.us-west-2.amazonaws.com/"
)

var (
	// 全局HTTP客户端池，减少连接创建开销
	httpClientPool = &sync.Pool{
		New: func() interface{} {
			return &http.Client{
				Timeout: 0, // 不设置超时，让大文件有足够时间上传
				Transport: &http.Transport{
					MaxIdleConns:        100,              // 最大空闲连接数
					MaxIdleConnsPerHost: 10,               // 每个主机的最大空闲连接数
					IdleConnTimeout:     90 * time.Second, // 空闲连接超时时间
					DisableCompression:  true,             // 禁用压缩以减少CPU使用
				},
			}
		},
	}

	// API客户端池，用于Notion API调用
	apiClientPool = &sync.Pool{
		New: func() interface{} {
			return &http.Client{
				Timeout: 30 * time.Second, // API调用设置合理超时
				Transport: &http.Transport{
					MaxIdleConns:        50,
					MaxIdleConnsPerHost: 5,
					IdleConnTimeout:     60 * time.Second,
					DisableCompression:  false, // API调用可以使用压缩
				},
			}
		},
	}
)

// getHTTPClient 从池中获取HTTP客户端
func getHTTPClient() *http.Client {
	return httpClientPool.Get().(*http.Client)
}

// putHTTPClient 将HTTP客户端放回池中
func putHTTPClient(client *http.Client) {
	httpClientPool.Put(client)
}

// getAPIClient 从池中获取API客户端
func getAPIClient() *http.Client {
	return apiClientPool.Get().(*http.Client)
}

// putAPIClient 将API客户端放回池中
func putAPIClient(client *http.Client) {
	apiClientPool.Put(client)
}

// ThrottledProgressTracker 节流的进度跟踪器
type ThrottledProgressTracker struct {
	totalSize       int64
	currentProgress int64
	lastReported    int64
	updateCallback  driver.UpdateProgress
	lastUpdateTime  time.Time
	updateInterval  time.Duration
	reportThreshold int64 // 进度变化阈值，避免微小变化的频繁更新
	mu              sync.Mutex
}

// NewThrottledProgressTracker 创建节流进度跟踪器
func NewThrottledProgressTracker(totalSize int64, callback driver.UpdateProgress) *ThrottledProgressTracker {
	return &ThrottledProgressTracker{
		totalSize:       totalSize,
		updateCallback:  callback,
		updateInterval:  200 * time.Millisecond, // 限制更新频率为每200ms
		reportThreshold: totalSize / 1000,       // 0.1%的变化才更新
	}
}

// Write 实现io.Writer接口，用于跟踪写入进度
func (t *ThrottledProgressTracker) Write(p []byte) (n int, err error) {
	n = len(p)
	t.mu.Lock()
	defer t.mu.Unlock()

	t.currentProgress += int64(n)

	// 检查是否需要更新进度
	now := time.Now()
	progressDiff := t.currentProgress - t.lastReported

	if progressDiff >= t.reportThreshold && now.Sub(t.lastUpdateTime) >= t.updateInterval {
		if t.updateCallback != nil {
			percentage := float64(t.currentProgress) * 100.0 / float64(t.totalSize)
			t.updateCallback(percentage)
		}
		t.lastReported = t.currentProgress
		t.lastUpdateTime = now
	}

	return n, nil
}

// OptimizedHashWriter 优化的哈希写入器，减少内存分配
type OptimizedHashWriter struct {
	hash           hash.Hash
	progressWriter io.Writer
	totalWritten   int64
}

// NewOptimizedHashWriter 创建优化的哈希写入器
func NewOptimizedHashWriter(progressWriter io.Writer) *OptimizedHashWriter {
	return &OptimizedHashWriter{
		hash:           sha1.New(),
		progressWriter: progressWriter,
	}
}

// Write 实现io.Writer接口
func (w *OptimizedHashWriter) Write(p []byte) (n int, err error) {
	// 同时写入哈希和进度跟踪器
	n, err = w.hash.Write(p)
	if err != nil {
		return n, err
	}

	w.totalWritten += int64(n)

	// 如果有进度跟踪器，也写入进度
	if w.progressWriter != nil {
		w.progressWriter.Write(p)
	}

	return n, nil
}

// Sum 获取哈希值
func (w *OptimizedHashWriter) Sum() string {
	return hex.EncodeToString(w.hash.Sum(nil))
}

func NewNotionService(cookie, token, spaceID, databaseID string, filePageID string) *NotionService {
	//从cookie中获取userId
	userId := extractUserID(cookie)
	if userId == "" {
		fmt.Println("无法从cookie中提取userId")
		return nil
	}
	// 创建 NotionService 实例
	return &NotionService{
		cookie:     cookie,
		token:      token,
		spaceID:    spaceID,
		databaseID: databaseID,
		filePageID: filePageID,
		userId:     userId,
	}
}

// extractUserID 从cookie字符串中提取 notion_user_id
func extractUserID(cookie string) string {
	// 查找 "notion_user_id=" 后面的部分
	start := strings.Index(cookie, "notion_user_id=")
	if start == -1 {
		return ""
	}
	start += len("notion_user_id=")

	// 查找 user_id 后的分号
	end := strings.Index(cookie[start:], ";")
	if end == -1 {
		end = len(cookie)
	} else {
		end += start
	}

	// 提取并返回 user_id
	return cookie[start:end]
}

// 计算文件的SHA1值
func (s *NotionService) CalculateFileSHA1(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *NotionService) CreateDatabasePage(title string) (string, error) {
	reqBody := CreatePageRequest{
		Parent: Parent{
			DatabaseID: s.databaseID,
		},
		Properties: Properties{
			Title: TitleProperty{
				Title: []TitleText{
					{
						Text: TextContent{
							Content: title,
						},
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("序列化请求体失败: %v", err)
	}

	req, err := http.NewRequest("POST", "https://api.notion.com/v1/pages", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置 Notion API 特定的请求头
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Notion-Version", "2022-06-28")
	req.Header.Set("Content-Type", "application/json")

	client := getAPIClient()
	defer putAPIClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("创建页面失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	var page CreatePageResponse
	err = json.Unmarshal(body, &page)
	if err != nil {
		return "", fmt.Errorf("解析响应体失败: %v", err)
	}
	// fmt.Printf("创建页面成功，页面ID: %s\n", page.ID)
	// fmt.Printf("页面创建成功，状态码: %d\n", resp.StatusCode)
	return page.ID, nil
}

func (s *NotionService) UploadAndUpdateFile(filePath string, id string) error {
	record := RecordInfo{
		Table:   "block",
		ID:      id,
		SpaceID: s.spaceID,
	}
	// 1. 上传文件到Notion
	uploadResponse, err := s.UploadFile(filePath, record)
	if err != nil {
		return fmt.Errorf("上传文件失败: %v", err)
	}

	// 2. 上传文件到S3
	err = s.UploadToS3(filePath, uploadResponse.Fields)
	if err != nil {
		return fmt.Errorf("上传到S3失败: %v", err)
	}

	fileName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filepath.Base(filePath)))
	// 3. 更新文件状态
	err = s.UpdateFileStatus(record, fileName, uploadResponse.URL)
	if err != nil {
		return fmt.Errorf("更新文件状态失败: %v", err)
	}

	return nil
}

func (s *NotionService) UploadAndUpdateFilePut(file model.FileStreamer, id string, up driver.UpdateProgress) (string, error) {
	record := RecordInfo{
		Table:   "block",
		ID:      id,
		SpaceID: s.spaceID,
	}
	// 1. 上传文件到Notion
	uploadResponse, err := s.UploadFilePut(file, record)
	if err != nil {
		return "", fmt.Errorf("上传文件失败: %v", err)
	}

	// 2. 上传文件到S3
	hash1, err := s.UploadToS3Put(file, uploadResponse, up)
	if err != nil {
		return "", fmt.Errorf("上传到S3失败: %v", err)
	}

	fileName := file.GetName()
	// 3. 更新文件状态
	err = s.UpdateFileStatus(record, fileName, uploadResponse.URL)

	if err != nil {
		return "", fmt.Errorf("更新文件状态失败: %v", err)
	}

	return hash1, nil
}

// GetContentType 根据文件后缀获取ContentType
func GetContentType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".mp4", ".m4v", ".mov", ".mkv":
		return "video/mp4"
	case ".mp3", ".wav", ".ogg":
		return "audio/mpeg"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".pdf":
		return "application/pdf"
	case ".doc", ".docx":
		return "application/msword"
	case ".xls", ".xlsx":
		return "application/vnd.ms-excel"
	case ".ppt", ".pptx":
		return "application/vnd.ms-powerpoint"
	case ".zip":
		return "application/zip"
	case ".rar":
		return "application/x-rar-compressed"
	case ".txt":
		return "text/plain"
	case ".html", ".htm":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	default:
		return "application/octet-stream"
	}
}

func (s *NotionService) UploadFile(filePath string, recordInfo RecordInfo) (*UploadResponse, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("无法读取文件: %v", err)
	}
	// 去除文件后缀
	fileName := strings.TrimSuffix(fileInfo.Name(), filepath.Ext(fileInfo.Name()))
	reqBody := UploadFileRequest{
		Bucket:              "secure",
		Name:                fileName,
		ContentType:         GetContentType(fileInfo.Name()),
		Record:              recordInfo,
		SupportExtraHeaders: true,
		ContentLength:       fileInfo.Size(),
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", NotionAPIBaseURL+"/getUploadFileUrl", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	s.setCommonHeaders(req)

	client := getAPIClient()
	defer putAPIClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	fmt.Printf("上传文件请求状态: %s\n", resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var uploadResponse UploadResponse
	err = json.Unmarshal(body, &uploadResponse)
	if err != nil {
		return nil, err
	}

	return &uploadResponse, nil
}

func (s *NotionService) UploadFilePut(file model.FileStreamer, recordInfo RecordInfo) (*UploadResponse, error) {
	fileName := file.GetName()
	reqBody := UploadFileRequest{
		Bucket:              "secure",
		Name:                fileName,
		ContentType:         file.GetMimetype(),
		Record:              recordInfo,
		SupportExtraHeaders: true,
		ContentLength:       file.GetSize(),
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", NotionAPIBaseURL+"/getUploadFileUrl", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	s.setPutCommonHeaders(req)

	client := getAPIClient()
	defer putAPIClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	fmt.Printf("上传文件请求状态: %s\n", resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var uploadResponse UploadResponse
	err = json.Unmarshal(body, &uploadResponse)
	if err != nil {
		return nil, err
	}

	return &uploadResponse, nil
}

func (s *NotionService) UploadToS3(filePath string, fields UploadFields) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("无法打开文件: %v", err)
	}
	defer file.Close()

	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %v", err)
	}
	fileSize := fileInfo.Size()
	// 创建带限速的文件流
	rateLimited := io.LimitReader(file, fileSize)

	// 创建 pipe，实现边写边读
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	// 计算 multipart 表单的边界长度
	boundary := writer.Boundary()
	boundaryPrefix := "--" + boundary + "\r\n"
	boundarySuffix := "\r\n--" + boundary + "--\r\n"
	boundaryLength := len(boundaryPrefix) + len(boundarySuffix)

	// 计算表单字段的总长度
	fieldsLength := 0
	// 每个字段的格式: Content-Disposition: form-data; name="fieldname"\r\n\r\nvalue\r\n
	fieldHeader := "Content-Disposition: form-data; name=\""
	fieldFooter := "\"\r\n\r\n"
	fieldEnd := "\r\n"

	fieldsLength += len(fieldHeader + "Content-Type" + fieldFooter + fields.ContentType + fieldEnd)
	fieldsLength += len(fieldHeader + "x-amz-storage-class" + fieldFooter + fields.XAmzStorageClass + fieldEnd)
	fieldsLength += len(fieldHeader + "tagging" + fieldFooter + fields.Tagging + fieldEnd)
	fieldsLength += len(fieldHeader + "bucket" + fieldFooter + fields.Bucket + fieldEnd)
	fieldsLength += len(fieldHeader + "X-Amz-Algorithm" + fieldFooter + fields.XAmzAlgorithm + fieldEnd)
	fieldsLength += len(fieldHeader + "X-Amz-Credential" + fieldFooter + fields.XAmzCredential + fieldEnd)
	fieldsLength += len(fieldHeader + "X-Amz-Date" + fieldFooter + fields.XAmzDate + fieldEnd)
	fieldsLength += len(fieldHeader + "X-Amz-Security-Token" + fieldFooter + fields.XAmzSecurityToken + fieldEnd)
	fieldsLength += len(fieldHeader + "key" + fieldFooter + fields.Key + fieldEnd)
	fieldsLength += len(fieldHeader + "Policy" + fieldFooter + fields.Policy + fieldEnd)
	fieldsLength += len(fieldHeader + "X-Amz-Signature" + fieldFooter + fields.XAmzSignature + fieldEnd)

	// 计算文件字段的头部长度
	fileHeader := "Content-Disposition: form-data; name=\"file\"; filename=\"" + filepath.Base(filePath) + "\"\r\n"
	fileHeader += "Content-Type: " + fields.ContentType + "\r\n\r\n"
	fileHeaderLength := len(fileHeader)

	// 计算总长度
	totalLength := int64(boundaryLength+fieldsLength+fileHeaderLength) + fileSize

	// 创建错误通道
	errChan := make(chan error, 1)

	// 异步写入 multipart 数据
	go func() {
		defer pw.Close()
		defer file.Close()

		// 写字段
		writer.WriteField("Content-Type", fields.ContentType)
		writer.WriteField("x-amz-storage-class", fields.XAmzStorageClass)
		writer.WriteField("tagging", fields.Tagging)
		writer.WriteField("bucket", fields.Bucket)
		writer.WriteField("X-Amz-Algorithm", fields.XAmzAlgorithm)
		writer.WriteField("X-Amz-Credential", fields.XAmzCredential)
		writer.WriteField("X-Amz-Date", fields.XAmzDate)
		writer.WriteField("X-Amz-Security-Token", fields.XAmzSecurityToken)
		writer.WriteField("key", fields.Key)
		writer.WriteField("Policy", fields.Policy)
		writer.WriteField("X-Amz-Signature", fields.XAmzSignature)

		// 写入文件字段
		part, err := writer.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			pw.CloseWithError(fmt.Errorf("创建文件字段失败: %v", err))
			return
		}

		// 使用带限速的文件流
		_, err = io.Copy(part, rateLimited)
		if err != nil {
			pw.CloseWithError(fmt.Errorf("复制文件内容失败: %v", err))
			return
		}

		writer.Close()
	}()

	// 创建请求
	req, err := http.NewRequestWithContext(context.Background(), "POST", S3BaseURL, pr)
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Content-Length", strconv.FormatInt(totalLength, 10))

	// 使用连接池中的客户端
	client := getHTTPClient()
	defer putHTTPClient(client)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查是否有写入错误
	select {
	case err := <-errChan:
		return err
	default:
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("文件上传成功，状态码: %d\n", resp.StatusCode)
	return nil
}

func (s *NotionService) UploadToS3Put(file model.FileStreamer, resp *UploadResponse, up driver.UpdateProgress) (string, error) {
	// 创建优化的进度跟踪器
	var progressTracker *ThrottledProgressTracker
	if up != nil {
		progressTracker = NewThrottledProgressTracker(file.GetSize(), up)
	}

	// 创建优化的哈希写入器，同时处理哈希和进度
	hashWriter := NewOptimizedHashWriter(progressTracker)
	tee := io.TeeReader(file, hashWriter)

	// 创建 HTTP 请求，使用流式上传
	req, err := http.NewRequest("PUT", resp.SignedPutUrl, tee)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}

	//设置请求头
	for _, header := range resp.PutHeaders {
		req.Header.Set(header.Name, header.Value)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	// 手动设置 Content-Length
	req.ContentLength = file.GetSize()

	// 使用连接池中的客户端
	client := getHTTPClient()
	defer putHTTPClient(client)

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("发送请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("上传失败，状态码: %d, 响应: %s", response.StatusCode, string(body))
	}
	// fmt.Printf("文件上传成功，状态码: %d\n", response.StatusCode)
	// 获取计算好的 SHA-1 值
	sha1Hex := hashWriter.Sum()
	return sha1Hex, nil
}

func (s *NotionService) UpdateFileStatus(record RecordInfo, fileName string, fileURL string) error {
	requestID := uuid.New().String()
	transactionID := uuid.New().String()
	currentTime := time.Now().UnixMilli()

	reqBody := UpdateFileStatusRequest{
		RequestID: requestID,
		Transactions: []Transaction{
			{
				ID:      transactionID,
				SpaceID: record.SpaceID,
				Debug: DebugInfo{
					UserAction: "BlockPropertyValueOverlay.renderFile",
				},
				Ops: []Operation{
					{
						Pointer: Pointer{
							ID:      record.ID,
							Table:   record.Table,
							SpaceID: record.SpaceID,
						},
						Path:    []string{"properties", s.filePageID},
						Command: "set",
						Args: []interface{}{
							[]interface{}{
								fileName,
								[]interface{}{
									[]interface{}{
										"a",
										fileURL,
									},
								},
							},
						},
					},
					{
						Pointer: Pointer{
							ID:      record.ID,
							Table:   record.Table,
							SpaceID: record.SpaceID,
						},
						Path:    []string{},
						Command: "update",
						Args: map[string]interface{}{
							"last_edited_time":     currentTime,
							"last_edited_by_id":    s.userId,
							"last_edited_by_table": "notion_user",
						},
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %v", err)
	}

	req, err := http.NewRequest("POST", NotionAPIBaseURL+"/saveTransactionsFanout", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	s.setCommonHeaders(req)

	client := getAPIClient()
	defer putAPIClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("更新文件状态失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	// fmt.Printf("文件状态更新成功，状态码: %d\n", resp.StatusCode)
	return nil
}

func (s *NotionService) setCommonHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("notion-client-version", "23.13.0.2948")
	req.Header.Set("notion-audit-log-platform", "web")
	req.Header.Set("Cookie", s.cookie)
}

func (s *NotionService) setPutCommonHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	// req.Header.Set("notion-client-version", "23.13.0.2948")
	// req.Header.Set("notion-audit-log-platform", "web")
	req.Header.Set("Cookie", s.cookie)
}

func (s *NotionService) GetPageProperty(pageID string, propertyID string) (*PropertyResponse, error) {
	//propertyID 转义
	propertyIDNew := url.PathEscape(propertyID)
	url := fmt.Sprintf("https://api.notion.com/v1/pages/%s/properties/%s", pageID, propertyIDNew)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Notion-Version", "2022-06-28")
	req.Header.Set("Content-Type", "application/json")

	client := getAPIClient()
	defer putAPIClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("获取属性失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var propertyResponse PropertyResponse
	if err := json.NewDecoder(resp.Body).Decode(&propertyResponse); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &propertyResponse, nil
}

// GetFileSize 获取文件大小
func GetFileSize(filePath string) (int64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return fileInfo.Size(), nil
}

// IsDir 判断是否为目录
func IsDir(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

// UploadChunkToS3Put 专门用于分块的流式上传，避免缓存
func (s *NotionService) UploadChunkToS3Put(reader io.Reader, size int64, resp *UploadResponse, up driver.UpdateProgress) (string, error) {
	// 创建优化的进度跟踪器
	var progressTracker *ThrottledProgressTracker
	if up != nil {
		progressTracker = NewThrottledProgressTracker(size, up)
	}

	// 创建优化的哈希写入器，同时处理哈希和进度
	hashWriter := NewOptimizedHashWriter(progressTracker)
	tee := io.TeeReader(reader, hashWriter)

	// 创建 HTTP 请求，使用流式上传
	req, err := http.NewRequest("PUT", resp.SignedPutUrl, tee)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}

	//设置请求头
	for _, header := range resp.PutHeaders {
		req.Header.Set(header.Name, header.Value)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	// 手动设置 Content-Length
	req.ContentLength = size

	// 使用连接池中的客户端
	client := getHTTPClient()
	defer putHTTPClient(client)

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("发送请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("上传失败，状态码: %d, 响应: %s", response.StatusCode, string(body))
	}
	// fmt.Printf("分块上传成功，状态码: %d\n", response.StatusCode)
	// 获取计算好的 SHA-1 值
	sha1Hex := hashWriter.Sum()
	return sha1Hex, nil
}

// UploadAndUpdateChunkPut 专门用于分块上传的方法
func (s *NotionService) UploadAndUpdateChunkPut(reader io.Reader, size int64, name string, id string, up driver.UpdateProgress) (string, error) {
	record := RecordInfo{
		Table:   "block",
		ID:      id,
		SpaceID: s.spaceID,
	}

	// 1. 获取上传URL
	uploadResponse, err := s.UploadChunkFilePut(name, size, record)
	if err != nil {
		return "", fmt.Errorf("获取上传URL失败: %v", err)
	}

	// 2. 直接上传到S3
	hash1, err := s.UploadChunkToS3Put(reader, size, uploadResponse, up)
	if err != nil {
		return "", fmt.Errorf("上传到S3失败: %v", err)
	}

	// 3. 更新文件状态
	err = s.UpdateFileStatus(record, name, uploadResponse.URL)
	if err != nil {
		return "", fmt.Errorf("更新文件状态失败: %v", err)
	}

	return hash1, nil
}

// UploadChunkFilePut 为分块上传获取上传URL
func (s *NotionService) UploadChunkFilePut(name string, size int64, recordInfo RecordInfo) (*UploadResponse, error) {
	reqBody := UploadFileRequest{
		Bucket:              "secure",
		Name:                name,
		ContentType:         "application/octet-stream",
		Record:              recordInfo,
		SupportExtraHeaders: true,
		ContentLength:       size,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", NotionAPIBaseURL+"/getUploadFileUrl", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	s.setPutCommonHeaders(req)

	client := getAPIClient()
	defer putAPIClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// fmt.Printf("获取分块上传URL状态: %s\n", resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var uploadResponse UploadResponse
	err = json.Unmarshal(body, &uploadResponse)
	if err != nil {
		return nil, err
	}

	return &uploadResponse, nil
}

// do others that not defined in Driver interface
