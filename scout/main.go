package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/chromedp"
)

type ScanResult struct {
	Target string   `json:"target"`
	Title  string   `json:"title"`
	Links  []string `json:"links"`
	Error  string   `json:"error,omitempty"`
}

func main() {
	targetURL := flag.String("target", "", "URL to scan")
	chromeURL := flag.String("chrome-url", "ws://chrome:9222", "WebSocket URL of Headless Chrome")
	flag.Parse()

	if *targetURL == "" {
		log.Fatal("Usage: ./scout -target <url> [-chrome-url <ws-url>]")
	}

	// Create allocator context (Remote Chrome)
	allocatorContext, cancel := chromedp.NewRemoteAllocator(context.Background(), *chromeURL)
	defer cancel()

	// Create request context
	ctx, cancel := chromedp.NewContext(allocatorContext)
	defer cancel()

	// Set timeout
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var title string
	var links []string
	
	// Run tasks
	// 1. Navigate
	// 2. Capture Title
	// 3. Extract Links (basic SPA spidering)
	err := chromedp.Run(ctx,
		chromedp.Navigate(*targetURL),
		chromedp.Title(&title),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a')).map(a => a.href)`, &links),
	)

	result := ScanResult{
		Target: *targetURL,
		Title:  title,
		Links:  links,
	}

	if err != nil {
		result.Error = err.Error()
	}

	// Print JSON to stdout for Python to parse
	output, _ := json.Marshal(result)
	fmt.Println(string(output))
}
