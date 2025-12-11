package kumo

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Extractor handles HTML parsing and link extraction
type Extractor struct{}

// NewExtractor creates a new extractor
func NewExtractor() *Extractor {
	return &Extractor{}
}

// ExtractLinks extracts links from HTML content
func (e *Extractor) ExtractLinks(
	ctx context.Context,
	htmlContent string,
	baseURL *url.URL,
) ([]string, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	var links []string
	var extractLinks func(*html.Node)
	baseHost := baseURL.Hostname()

	extractLinks = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					href := attr.Val
					absoluteURL, err := baseURL.Parse(href)
					if err != nil {
						continue
					}

					// Only spider same domain
					if absoluteURL.Hostname() == baseHost {
						links = append(links, absoluteURL.String())
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractLinks(c)
		}
	}

	extractLinks(doc)
	return links, nil
}

// LinkData represents extracted link information
type LinkData struct {
	Href        string
	AbsoluteURL string
	Text        string
	Title       string
	Rel         []string
}

// ExtractLinksEnhanced extracts links with enhanced analysis
func (e *Extractor) ExtractLinksEnhanced(
	ctx context.Context,
	htmlContent string,
	baseURL *url.URL,
) ([]LinkData, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	var links []LinkData
	var extractLinks func(*html.Node)
	baseHost := baseURL.Hostname()

	extractLinks = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			linkData := LinkData{}
			var href string

			for _, attr := range n.Attr {
				switch attr.Key {
				case "href":
					href = attr.Val
					linkData.Href = href
				case "title":
					linkData.Title = attr.Val
				case "rel":
					linkData.Rel = strings.Fields(attr.Val)
				}
			}

			if href != "" {
				absoluteURL, err := baseURL.Parse(href)
				if err == nil {
					linkData.AbsoluteURL = absoluteURL.String()

					// Only spider same domain
					if absoluteURL.Hostname() == baseHost {
						// Extract text content
						linkData.Text = extractText(n)
						links = append(links, linkData)
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractLinks(c)
		}
	}

	extractLinks(doc)
	return links, nil
}

// extractText extracts text content from a node
func extractText(n *html.Node) string {
	var text strings.Builder
	var extract func(*html.Node)

	extract = func(node *html.Node) {
		if node.Type == html.TextNode {
			text.WriteString(strings.TrimSpace(node.Data))
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(n)
	return strings.TrimSpace(text.String())
}

