package notion

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
)

// CycleTLSClient 包装CycleTLS客户端以处理反CF保护
type CycleTLSClient struct {
	client  cycletls.CycleTLS
	mu      sync.RWMutex
	timeout time.Duration
}

// NewCycleTLSClient 创建一个新的CycleTLS客户端实例
func NewCycleTLSClient() *CycleTLSClient {
	// 初始化CycleTLS客户端，使用最新的Chrome指纹
	client := cycletls.Init()

	return &CycleTLSClient{
		client:  client,
		timeout: 30 * time.Second, // 默认30秒超时
	}
}

// Close 关闭CycleTLS客户端
func (c *CycleTLSClient) Close() {
	c.client.Close()
}

// SetTimeout 设置请求超时时间
func (c *CycleTLSClient) SetTimeout(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = timeout
}

// generateJA3 生成随机的JA3指纹来模拟不同的浏览器
func (c *CycleTLSClient) generateJA3() string {
	// Chrome的常见JA3指纹列表
	ja3Fingerprints := []string{
		"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0",
		"771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,65281-0-23-35-13-5-18-16-30032-11-10-51-45-43-27-21,29-23-24-25,0",
	}

	rand.Seed(time.Now().UnixNano())
	return ja3Fingerprints[rand.Intn(len(ja3Fingerprints))]
}

// generateUserAgent 生成随机的User-Agent
func (c *CycleTLSClient) generateUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}

	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}

// DoRequest 执行HTTP请求，自动处理CF保护
func (c *CycleTLSClient) DoRequest(ctx context.Context, options cycletls.Options) (*cycletls.Response, error) {
	// 设置基础的反CF检测配置
	if options.Ja3 == "" {
		options.Ja3 = c.generateJA3()
	}

	if options.UserAgent == "" {
		options.UserAgent = c.generateUserAgent()
	}

	// 设置默认头部
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	// 添加必要的反CF检测头部
	c.setAntiCFHeaders(options.Headers, options.URL)

	// 设置超时
	if options.Timeout == 0 {
		options.Timeout = int(c.timeout.Seconds())
	}

	// 执行请求，带重试机制
	maxRetries := 3
	var lastResp *cycletls.Response
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := c.client.Do(options.URL, options, options.Method)
		if err != nil {
			lastErr = err
			if attempt < maxRetries {
				// 指数退避重试
				backoffTime := time.Duration(1<<uint(attempt)) * time.Second
				jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
				time.Sleep(backoffTime + jitter)
				continue
			}
			return nil, fmt.Errorf("请求失败，重试%d次后仍失败: %v", maxRetries, err)
		}

		lastResp = &resp

		// 检查是否被CF拦截
		if c.isCloudflareBlocked(resp) {
			if attempt < maxRetries {
				fmt.Printf("检测到CF拦截，状态码: %d，第%d次重试\n", resp.Status, attempt+1)

				// 更换指纹和User-Agent
				options.Ja3 = c.generateJA3()
				options.UserAgent = c.generateUserAgent()

				// 增加随机延时避免检测
				time.Sleep(time.Duration(2+rand.Intn(5)) * time.Second)
				continue
			}
			return nil, fmt.Errorf("经过%d次重试后仍被Cloudflare拦截", maxRetries)
		}

		// 请求成功
		return lastResp, nil
	}

	return lastResp, lastErr
}

// isCloudflareBlocked 检测是否被Cloudflare拦截
func (c *CycleTLSClient) isCloudflareBlocked(resp cycletls.Response) bool {
	// 检查状态码
	if resp.Status == 403 || resp.Status == 503 || resp.Status == 429 {
		return true
	}

	// 检查响应头
	for key, value := range resp.Headers {
		lowerKey := strings.ToLower(key)
		lowerValue := strings.ToLower(value)

		// Cloudflare特有的响应头
		if lowerKey == "server" && strings.Contains(lowerValue, "cloudflare") {
			if resp.Status != 200 {
				return true
			}
		}

		if lowerKey == "cf-ray" && resp.Status != 200 {
			return true
		}
	}

	// 检查响应体中的Cloudflare特征
	bodyLower := strings.ToLower(resp.Body)
	cfSignatures := []string{
		"cloudflare",
		"checking your browser",
		"ddos protection by cloudflare",
		"ray id:",
		"cf-browser-verification",
		"__cf_bm",
		"cf_clearance",
	}

	for _, signature := range cfSignatures {
		if strings.Contains(bodyLower, signature) && resp.Status != 200 {
			return true
		}
	}

	return false
}

// setAntiCFHeaders 设置反CF检测的HTTP头部
func (c *CycleTLSClient) setAntiCFHeaders(headers map[string]string, url string) {
	// 基础浏览器头部
	headers["Accept"] = "*/*"
	headers["Accept-Language"] = "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"
	headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
	headers["Cache-Control"] = "no-cache"
	headers["Pragma"] = "no-cache"
	headers["DNT"] = "1"

	// 针对Notion的特殊头部
	if strings.Contains(url, "notion.so") {
		headers["Origin"] = "https://www.notion.so"
		headers["Referer"] = "https://www.notion.so/"
		headers["sec-ch-ua"] = `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`
		headers["sec-ch-ua-mobile"] = "?0"
		headers["sec-ch-ua-platform"] = `"Windows"`
		headers["sec-fetch-dest"] = "empty"
		headers["sec-fetch-mode"] = "cors"
		headers["sec-fetch-site"] = "same-origin"
		headers["upgrade-insecure-requests"] = "1"
	}

	// 连接相关头部
	headers["Connection"] = "keep-alive"
	headers["Keep-Alive"] = "timeout=60"
}

// DoNotionAPIRequest 专门用于Notion API请求的方法
func (c *CycleTLSClient) DoNotionAPIRequest(ctx context.Context, method, url string, body []byte, headers map[string]string) (*cycletls.Response, error) {
	options := cycletls.Options{
		Method:    method,
		URL:       url,
		Headers:   headers,
		Timeout:   30,
		UserAgent: c.generateUserAgent(),
		Ja3:       c.generateJA3(),
	}

	// 设置请求体
	if body != nil {
		options.Body = string(body)
	}

	// 设置默认Content-Type
	if options.Headers["Content-Type"] == "" && method != "GET" {
		options.Headers["Content-Type"] = "application/json"
	}

	return c.DoRequest(ctx, options)
}
