package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/google/uuid"
)

const (
	NotionAPIBaseURL = "https://www.notion.so/api/v3"
)

func NewNotionService(cookie, token, spaceID, databaseID string, filePageID string) *NotionService {
	//从cookie中获取userId
	userId := extractUserID(cookie)
	if userId == "" {
		fmt.Println("无法从cookie中提取userId")
		return nil
	}
	// 创建 NotionService 实例
	return &NotionService{
		cookie:         cookie,
		token:          token,
		spaceID:        spaceID,
		databaseID:     databaseID,
		filePageID:     filePageID,
		userId:         userId,
		cycleTLSClient: NewCycleTLSClient(), // 初始化CycleTLS客户端
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

	client := &http.Client{}
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

func (s *NotionService) UploadAndUpdateFilePut(file model.FileStreamer, id string, up driver.UpdateProgress) error {
	record := RecordInfo{
		Table:   "block",
		ID:      id,
		SpaceID: s.spaceID,
	}
	// 1. 上传文件到Notion
	uploadResponse, err := s.UploadFilePut(file, record)
	if err != nil {
		return fmt.Errorf("上传文件失败: %v", err)
	}

	// 2. 上传文件到S3
	err = s.UploadToS3Put(file, uploadResponse, up)
	if err != nil {
		return fmt.Errorf("上传到S3失败: %v", err)
	}

	fileName := file.GetName()
	// 3. 更新文件状态
	err = s.UpdateFileStatus(record, fileName, uploadResponse.URL)

	if err != nil {
		return fmt.Errorf("更新文件状态失败: %v", err)
	}

	return nil
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

	// 准备请求头
	headers := map[string]string{
		"Cookie":                      s.cookie,
		"X-Notion-Active-User-Header": s.userId,
		"X-Notion-Space-Id":           s.spaceID,
	}

	// 使用CycleTLS发送请求
	ctx := context.Background()
	resp, err := s.cycleTLSClient.DoNotionAPIRequest(ctx, "POST", NotionAPIBaseURL+"/getUploadFileUrl", jsonData, headers)
	if err != nil {
		return nil, fmt.Errorf("上传文件请求失败: %v", err)
	}

	fmt.Printf("上传文件请求状态: %d\n", resp.Status)
	fmt.Printf("上传文件响应: %s\n", resp.Body)

	var uploadResponse UploadResponse
	err = json.Unmarshal([]byte(resp.Body), &uploadResponse)
	if err != nil {
		return nil, err
	}

	return &uploadResponse, nil
}

func (s *NotionService) UploadToS3Put(file model.FileStreamer, resp *UploadResponse, up driver.UpdateProgress) error {
	// 创建进度跟踪器
	var reader io.Reader = file
	if up != nil {
		progress := driver.NewProgress(file.GetSize(), up)
		reader = io.TeeReader(file, progress)
	}

	// 创建 HTTP 请求，使用流式上传
	req, err := http.NewRequest("PUT", resp.SignedPutUrl, reader)
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	//设置请求头
	for _, header := range resp.PutHeaders {
		req.Header.Set(header.Name, header.Value)
	}
	// req.Header.Set("Content-Type", "application/octet-stream")
	// 手动设置 Content-Length
	req.ContentLength = file.GetSize()

	// 创建支持流式上传的 HTTP 客户端
	client := &http.Client{
		Timeout: 0, // 不设置超时，让大文件有足够时间上传
	}

	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("上传失败，状态码: %d, 响应: %s", response.StatusCode, string(body))
	}
	fmt.Printf("文件上传成功，状态码: %d\n", response.StatusCode)
	return nil
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

	// 准备请求头
	headers := map[string]string{
		"Cookie":                      s.cookie,
		"X-Notion-Active-User-Header": s.userId,
		"X-Notion-Space-Id":           s.spaceID,
	}

	// 使用CycleTLS发送更新文件状态请求
	ctx := context.Background()
	resp, err := s.cycleTLSClient.DoNotionAPIRequest(ctx, "POST", NotionAPIBaseURL+"/saveTransactionsFanout", jsonData, headers)
	if err != nil {
		return fmt.Errorf("更新文件状态请求失败: %v", err)
	}

	if resp.Status != 200 {
		return fmt.Errorf("更新文件状态失败，状态码: %d, 响应: %s", resp.Status, resp.Body)
	}

	// fmt.Printf("文件状态更新成功，状态码: %d\n", resp.Status)
	return nil
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

	client := &http.Client{}
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

// UploadChunkToS3Put 专门用于分块的流式上传，避免缓存
func (s *NotionService) UploadChunkToS3Put(reader io.Reader, size int64, resp *UploadResponse, up driver.UpdateProgress) error {
	// 创建进度跟踪器
	var uploadReader io.Reader = reader
	if up != nil {
		progress := driver.NewProgress(size, up)
		uploadReader = io.TeeReader(reader, progress)
	}

	// 创建 HTTP 请求，使用流式上传
	req, err := http.NewRequest("PUT", resp.SignedPutUrl, uploadReader)
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	//设置请求头
	for _, header := range resp.PutHeaders {
		req.Header.Set(header.Name, header.Value)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	// 手动设置 Content-Length
	req.ContentLength = size

	// 创建支持流式上传的 HTTP 客户端
	client := &http.Client{
		Timeout: 0, // 不设置超时，让大文件有足够时间上传
	}

	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("上传失败，状态码: %d, 响应: %s", response.StatusCode, string(body))
	}
	// fmt.Printf("分块上传成功，状态码: %d\n", response.StatusCode)
	return nil
}

// UploadAndUpdateChunkPut 专门用于分块上传的方法
func (s *NotionService) UploadAndUpdateChunkPut(reader io.Reader, size int64, name string, id string, up driver.UpdateProgress) error {
	record := RecordInfo{
		Table:   "block",
		ID:      id,
		SpaceID: s.spaceID,
	}

	// 1. 获取上传URL
	uploadResponse, err := s.UploadChunkFilePut(name, size, record)
	if err != nil {
		return fmt.Errorf("获取上传URL失败: %v", err)
	}

	// 2. 直接上传到S3
	err = s.UploadChunkToS3Put(reader, size, uploadResponse, up)
	if err != nil {
		return fmt.Errorf("上传到S3失败: %v", err)
	}

	// 3. 更新文件状态
	err = s.UpdateFileStatus(record, name, uploadResponse.URL)
	if err != nil {
		return fmt.Errorf("更新文件状态失败: %v", err)
	}

	return nil
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

	// 准备请求头
	headers := map[string]string{
		"Cookie":                      s.cookie,
		"X-Notion-Active-User-Header": s.userId,
		"X-Notion-Space-Id":           s.spaceID,
	}

	// 使用CycleTLS发送分块上传URL请求
	ctx := context.Background()
	resp, err := s.cycleTLSClient.DoNotionAPIRequest(ctx, "POST", NotionAPIBaseURL+"/getUploadFileUrl", jsonData, headers)
	if err != nil {
		return nil, fmt.Errorf("获取分块上传URL失败: %v", err)
	}

	// fmt.Printf("获取分块上传URL状态: %d\n", resp.Status)

	var uploadResponse UploadResponse
	err = json.Unmarshal([]byte(resp.Body), &uploadResponse)
	if err != nil {
		return nil, err
	}

	return &uploadResponse, nil
}

// UploadFilePutWithCurl 使用系统curl命令发送请求的版本，不依赖cycleTLSClient
func (s *NotionService) UploadFilePutWithCurl(file model.FileStreamer, recordInfo RecordInfo) (*UploadResponse, error) {
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

	// 构建curl命令和参数
	curlCmd, err := s.buildCurlCommand("POST", NotionAPIBaseURL+"/getUploadFileUrl", jsonData)
	if err != nil {
		return nil, fmt.Errorf("构建curl命令失败: %v", err)
	}

	// 执行curl命令
	output, err := s.executeCurlCommand(curlCmd)
	if err != nil {
		return nil, fmt.Errorf("执行curl命令失败: %v", err)
	}

	fmt.Printf("上传文件curl响应: %s\n", output)

	var uploadResponse UploadResponse
	err = json.Unmarshal([]byte(output), &uploadResponse)
	if err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &uploadResponse, nil
}

// buildCurlCommand 构建curl命令和参数
func (s *NotionService) buildCurlCommand(method, url string, body []byte) ([]string, error) {
	args := []string{
		"curl",
		"-X", method,
		"-H", "Content-Type: application/json",
		"-H", "Cookie: " + s.cookie,
		"-H", "X-Notion-Active-User-Header: " + s.userId,
		"-H", "X-Notion-Space-Id: " + s.spaceID,
	}

	// 添加请求体
	if body != nil && len(body) > 0 {
		args = append(args, "-d", string(body))
	}

	// 添加URL
	args = append(args, url)

	return args, nil
}

// executeCurlCommand 执行curl命令并返回响应
func (s *NotionService) executeCurlCommand(args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)

	// 捕获标准输出和标准错误
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("curl命令执行失败: %v, stderr: %s", err, stderr.String())
	}

	output := stdout.String()
	if output == "" {
		return "", fmt.Errorf("curl命令返回空响应")
	}

	return output, nil
}

// UpdateFileStatusWithCurl 使用curl更新文件状态的版本
func (s *NotionService) UpdateFileStatusWithCurl(record RecordInfo, fileName string, fileURL string) error {
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

	// 构建curl命令
	curlCmd, err := s.buildCurlCommand("POST", NotionAPIBaseURL+"/saveTransactionsFanout", jsonData)
	if err != nil {
		return fmt.Errorf("构建curl命令失败: %v", err)
	}

	// 执行curl命令
	output, err := s.executeCurlCommand(curlCmd)
	if err != nil {
		return fmt.Errorf("更新文件状态curl命令失败: %v", err)
	}

	// 检查响应是否成功（这里假设成功的响应不为空）
	if output == "" {
		return fmt.Errorf("更新文件状态失败: 空响应")
	}

	return nil
}

// UploadAndUpdateFilePutWithCurl 使用curl的完整上传和更新流程
func (s *NotionService) UploadAndUpdateFilePutWithCurl(file model.FileStreamer, id string, up driver.UpdateProgress) error {
	record := RecordInfo{
		Table:   "block",
		ID:      id,
		SpaceID: s.spaceID,
	}

	// 1. 使用curl上传文件到Notion获取上传URL
	uploadResponse, err := s.UploadFilePutWithCurl(file, record)
	if err != nil {
		return fmt.Errorf("使用curl上传文件失败: %v", err)
	}

	// 2. 上传文件到S3 (这部分保持不变，因为直接使用HTTP客户端更合适)
	err = s.UploadToS3Put(file, uploadResponse, up)
	if err != nil {
		return fmt.Errorf("上传到S3失败: %v", err)
	}

	fileName := file.GetName()
	// 3. 使用curl更新文件状态
	err = s.UpdateFileStatusWithCurl(record, fileName, uploadResponse.URL)
	if err != nil {
		return fmt.Errorf("使用curl更新文件状态失败: %v", err)
	}

	return nil
}

// UploadChunkFilePutWithCurl 使用curl为分块上传获取上传URL
func (s *NotionService) UploadChunkFilePutWithCurl(name string, size int64, recordInfo RecordInfo) (*UploadResponse, error) {
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

	// 构建curl命令
	curlCmd, err := s.buildCurlCommand("POST", NotionAPIBaseURL+"/getUploadFileUrl", jsonData)
	if err != nil {
		return nil, fmt.Errorf("构建curl命令失败: %v", err)
	}

	// 执行curl命令
	output, err := s.executeCurlCommand(curlCmd)
	if err != nil {
		return nil, fmt.Errorf("获取分块上传URL失败: %v", err)
	}

	var uploadResponse UploadResponse
	err = json.Unmarshal([]byte(output), &uploadResponse)
	if err != nil {
		return nil, err
	}

	return &uploadResponse, nil
}

// UploadAndUpdateChunkPutWithCurl 使用curl的分块上传方法
func (s *NotionService) UploadAndUpdateChunkPutWithCurl(reader io.Reader, size int64, name string, id string, up driver.UpdateProgress) error {
	record := RecordInfo{
		Table:   "block",
		ID:      id,
		SpaceID: s.spaceID,
	}

	// 1. 使用curl获取上传URL
	uploadResponse, err := s.UploadChunkFilePutWithCurl(name, size, record)
	if err != nil {
		return fmt.Errorf("使用curl获取上传URL失败: %v", err)
	}

	// 2. 直接上传到S3 (保持使用HTTP客户端，因为更适合大文件流式上传)
	err = s.UploadChunkToS3Put(reader, size, uploadResponse, up)
	if err != nil {
		return fmt.Errorf("上传到S3失败: %v", err)
	}

	// 3. 使用curl更新文件状态
	err = s.UpdateFileStatusWithCurl(record, name, uploadResponse.URL)
	if err != nil {
		return fmt.Errorf("使用curl更新文件状态失败: %v", err)
	}

	return nil
}

// do others that not defined in Driver interface
