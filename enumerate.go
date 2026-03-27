package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Common subdomain wordlist (top 200 most common)
var subdomainWordlist = []string{
	"www", "mail", "remote", "blog", "webmail", "server",
	"ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
	"ftp", "mail2", "test", "portal", "ns", "ww1", "host",
	"support", "dev", "web", "bbs", "ww42", "mx", "email",
	"cloud", "1", "mail1", "2", "forum", "owa", "www2",
	"gw", "admin", "store", "mx1", "cdn", "api", "exchange",
	"app", "gov", "2tty", "vps", "govyty", "hmail", "dns",
	"dns1", "dns2", "access", "monitor", "login", "ssl",
	"staging", "stage", "beta", "qa", "uat", "demo",
	"sandbox", "internal", "intranet", "extranet", "proxy",
	"gateway", "gw1", "gw2", "firewall", "fw", "fw1",
	"lb", "lb1", "lb2", "load", "balancer", "haproxy",
	"nginx", "apache", "iis", "tomcat", "jboss",
	"db", "db1", "db2", "database", "mysql", "postgres",
	"postgresql", "mongo", "mongodb", "redis", "elastic",
	"elasticsearch", "solr", "cassandra", "memcached",
	"mq", "rabbit", "rabbitmq", "kafka", "activemq",
	"ldap", "ad", "dc", "dc1", "dc2", "dns3",
	"ntp", "time", "log", "logs", "syslog", "splunk",
	"nagios", "zabbix", "prometheus", "grafana", "kibana",
	"jenkins", "ci", "cd", "gitlab", "git", "svn",
	"bitbucket", "jira", "confluence", "wiki", "docs",
	"help", "helpdesk", "ticket", "tickets", "service",
	"servicedesk", "status", "health", "check",
	"backup", "bak", "bk", "dr", "disaster",
	"img", "images", "image", "static", "assets",
	"media", "upload", "uploads", "download", "downloads",
	"files", "file", "share", "shares", "storage",
	"s3", "bucket", "blob", "archive",
	"video", "stream", "streaming", "live", "rtmp",
	"voip", "sip", "pbx", "phone", "tel",
	"chat", "im", "xmpp", "jabber", "irc",
	"crm", "erp", "sap", "oracle", "salesforce",
	"hr", "payroll", "finance", "accounting",
	"vpn1", "vpn2", "ras", "citrix", "rdp", "terminal",
	"jump", "jumpbox", "bastion", "ssh",
	"k8s", "kube", "kubernetes", "docker", "container",
	"registry", "harbor", "nexus", "artifactory",
	"dev1", "dev2", "test1", "test2", "staging1",
	"prod", "production", "prd", "stg",
	"us", "eu", "ap", "east", "west", "central",
	"node1", "node2", "node3", "worker", "master",
	"primary", "secondary", "replica",
	"mx2", "mx3", "smtp1", "smtp2", "pop", "pop3",
	"imap", "webmail2", "autodiscover", "autoconfig",
	"mta", "relay", "postfix", "sendmail",
	"www1", "www3", "web1", "web2", "site",
	"cms", "wordpress", "wp", "drupal", "magento",
	"mobile", "api2", "api3", "rest", "graphql",
	"auth", "oauth", "sso", "identity", "idp",
	"dashboard", "panel", "console", "manage",
}

// CertTransparencyResult from crt.sh API
type CertTransparencyResult struct {
	NameValue string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// EnumerateSubdomains discovers subdomains using multiple methods
func EnumerateSubdomains(ctx context.Context, domain string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite, color.Bold)
	green := color.New(color.FgGreen)
	dim := color.New(color.FgWhite)

	white.Printf("\n  Enumerating subdomains for %s...\n\n", domain)

	var allSubdomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Method 1: Certificate Transparency Logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		cyan.Printf("  📜 Querying Certificate Transparency logs...")

		ctResults, err := queryCertTransparency(ctx, domain)
		if err != nil {
			color.Red(" error: %v\n", err)
			return
		}

		mu.Lock()
		allSubdomains = append(allSubdomains, ctResults...)
		mu.Unlock()

		green.Printf(" found %d subdomains\n", len(ctResults))
	}()

	// Method 2: DNS brute-force
	wg.Add(1)
	go func() {
		defer wg.Done()
		cyan.Printf("  🔍 DNS brute-force (%d words)...", len(subdomainWordlist))

		dnsResults, err := dnsBruteForce(ctx, domain)
		if err != nil {
			color.Red(" error: %v\n", err)
			return
		}

		mu.Lock()
		allSubdomains = append(allSubdomains, dnsResults...)
		mu.Unlock()

		green.Printf(" found %d subdomains\n", len(dnsResults))
	}()

	// Method 3: Common DNS records
	wg.Add(1)
	go func() {
		defer wg.Done()
		cyan.Printf("  📋 Checking DNS records (MX, NS, TXT)...")

		dnsRecResults, err := checkDNSRecords(ctx, domain)
		if err != nil {
			color.Red(" error: %v\n", err)
			return
		}

		mu.Lock()
		allSubdomains = append(allSubdomains, dnsRecResults...)
		mu.Unlock()

		green.Printf(" found %d subdomains\n", len(dnsRecResults))
	}()

	wg.Wait()

	// Always include the base domain
	allSubdomains = append(allSubdomains, domain)

	// Deduplicate and clean
	unique := deduplicateAndClean(allSubdomains, domain)

	// Sort alphabetically
	sort.Strings(unique)

	fmt.Println()
	white.Printf("  Total unique subdomains: %d\n\n", len(unique))

	// Print discovered subdomains
	if len(unique) <= 30 {
		for i, sub := range unique {
			prefix := "  ├─"
			if i == len(unique)-1 {
				prefix = "  └─"
			}
			dim.Printf("%s %s\n", prefix, sub)
		}
	} else {
		for i := 0; i < 15; i++ {
			dim.Printf("  ├─ %s\n", unique[i])
		}
		dim.Printf("  ├─ ... %d more ...\n", len(unique)-20)
		for i := len(unique) - 5; i < len(unique); i++ {
			prefix := "  ├─"
			if i == len(unique)-1 {
				prefix = "  └─"
			}
			dim.Printf("%s %s\n", prefix, unique[i])
		}
	}
	fmt.Println()

	return unique, nil
}

// queryCertTransparency queries crt.sh for subdomains
func queryCertTransparency(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pqscan/0.1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	// Read body with size limit (10MB max)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var results []CertTransparencyResult
	err = json.Unmarshal(body, &results)
	if err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	// Extract unique subdomains
	seen := make(map[string]bool)
	var subdomains []string

	for _, r := range results {
		// name_value can contain multiple domains separated by newlines
		names := strings.Split(r.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))

			// Remove wildcard prefix
			name = strings.TrimPrefix(name, "*.")

			// Skip empty, invalid, or non-matching domains
			if name == "" {
				continue
			}
			if !strings.HasSuffix(name, "."+domain) && name != domain {
				continue
			}

			// Skip if already seen
			if seen[name] {
				continue
			}
			seen[name] = true

			subdomains = append(subdomains, name)
		}
	}

	return subdomains, nil
}

// dnsBruteForce tries common subdomain names via DNS resolution
func dnsBruteForce(ctx context.Context, domain string) ([]string, error) {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrent DNS queries
	sem := make(chan struct{}, 50)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	for _, word := range subdomainWordlist {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			subdomain := fmt.Sprintf("%s.%s", w, domain)

			lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			ips, err := resolver.LookupIPAddr(lookupCtx, subdomain)
			if err != nil {
				return
			}

			if len(ips) > 0 {
				mu.Lock()
				found = append(found, subdomain)
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()
	return found, nil
}

// checkDNSRecords checks MX, NS, and other DNS records for subdomains
func checkDNSRecords(ctx context.Context, domain string) ([]string, error) {
	var found []string

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// MX records
	mxRecords, err := resolver.LookupMX(lookupCtx, domain)
	if err == nil {
		for _, mx := range mxRecords {
			host := strings.TrimSuffix(strings.ToLower(mx.Host), ".")
			if strings.HasSuffix(host, "."+domain) || host == domain {
				found = append(found, host)
			}
		}
	}

	// NS records
	nsRecords, err := resolver.LookupNS(lookupCtx, domain)
	if err == nil {
		for _, ns := range nsRecords {
			host := strings.TrimSuffix(strings.ToLower(ns.Host), ".")
			if strings.HasSuffix(host, "."+domain) || host == domain {
				found = append(found, host)
			}
		}
	}

	// SRV records for common services
	srvServices := []string{
		"_sip._tcp", "_sip._udp", "_xmpp-client._tcp",
		"_xmpp-server._tcp", "_jabber._tcp",
		"_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
		"_http._tcp", "_https._tcp",
		"_imap._tcp", "_imaps._tcp",
		"_submission._tcp", "_pop3._tcp", "_pop3s._tcp",
		"_autodiscover._tcp",
	}

	for _, svc := range srvServices {
		srvCtx, srvCancel := context.WithTimeout(ctx, 3*time.Second)
		_, srvRecords, err := resolver.LookupSRV(srvCtx, "", "", svc+"."+domain)
		srvCancel()

		if err == nil {
			for _, srv := range srvRecords {
				host := strings.TrimSuffix(strings.ToLower(srv.Target), ".")
				if strings.HasSuffix(host, "."+domain) || host == domain {
					found = append(found, host)
				}
			}
		}
	}

	// TXT records (sometimes contain references to subdomains)
	txtRecords, err := resolver.LookupTXT(lookupCtx, domain)
	if err == nil {
		for _, txt := range txtRecords {
			// Look for SPF includes which reference mail infrastructure
			if strings.Contains(txt, "include:") {
				parts := strings.Split(txt, " ")
				for _, part := range parts {
					if strings.HasPrefix(part, "include:") {
						host := strings.TrimPrefix(part, "include:")
						host = strings.ToLower(host)
						if strings.HasSuffix(host, "."+domain) {
							found = append(found, host)
						}
					}
				}
			}
		}
	}

	// CNAME for common subdomains
	commonCNAME := []string{
		"autodiscover", "lyncdiscover", "sip",
		"enterpriseregistration", "enterpriseenrollment",
		"_dmarc",
	}

	for _, sub := range commonCNAME {
		cnameCtx, cnameCanel := context.WithTimeout(ctx, 3*time.Second)
		cname, err := resolver.LookupCNAME(cnameCtx, sub+"."+domain)
		cnameCanel()

		if err == nil && cname != "" {
			found = append(found, sub+"."+domain)
		}
	}

	return found, nil
}

// deduplicateAndClean removes duplicates and invalid entries
func deduplicateAndClean(subdomains []string, baseDomain string) []string {
	seen := make(map[string]bool)
	var unique []string

	baseDomain = strings.ToLower(baseDomain)

	for _, sub := range subdomains {
		// Clean up
		sub = strings.TrimSpace(strings.ToLower(sub))
		sub = strings.TrimSuffix(sub, ".")

		// Remove wildcard
		sub = strings.TrimPrefix(sub, "*.")

		// Skip empty
		if sub == "" {
			continue
		}

		// Must be part of the target domain
		if sub != baseDomain && !strings.HasSuffix(sub, "."+baseDomain) {
			continue
		}

		// Skip already seen
		if seen[sub] {
			continue
		}

		// Skip very long subdomains (likely garbage)
		if len(sub) > 253 {
			continue
		}

		// Skip subdomains with invalid characters
		valid := true
		for _, c := range sub {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}

		seen[sub] = true
		unique = append(unique, sub)
	}

	return unique
}

// ResolveSubdomain checks if a subdomain resolves and returns IPs
func ResolveSubdomain(ctx context.Context, subdomain string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(lookupCtx, subdomain)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result, nil
}