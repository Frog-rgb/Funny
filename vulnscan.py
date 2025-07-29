#!/usr/bin/env python3
"""
Ethical Web Vulnerability Scanner Pro
Designed for professional security testing in CTFs and Bug Bounty programs
USE ONLY ON AUTHORIZED SYSTEMS WITH EXPLICIT PERMISSION
"""

import requests
import argparse
import urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import os
import sys
import json
import time
import random
import socket
import dns.resolver
from urllib.robotparser import RobotFileParser
from tldextract import extract
import xml.etree.ElementTree as ET
import hashlib
import zlib
from http.client import HTTPConnection

# Constants
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]
MAX_THREADS = 15
REQUEST_DELAY = 0.5  # seconds between requests
TIMEOUT = 15
MAX_REDIRECTS = 5
SIGNATURE_DB = "vuln_signatures.json"

class VulnerabilityScannerPro:
    def __init__(self, target_url, output_file=None, verbose=False, intensive=False):
        self.target_url = self.normalize_url(target_url)
        self.output_file = output_file
        self.verbose = verbose
        self.intensive = intensive  # More thorough but slower scanning
        self.session = requests.Session()
        self.session.max_redirects = MAX_REDIRECTS
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.robots_parser = RobotFileParser()
        self.tech_stack = {}
        self.load_balancers = set()
        self.subdomains = set()
        self.cookies = {}
        self.vuln_signatures = self.load_vulnerability_signatures()
        
        # Enhanced HTTP client with debugging for verbose mode
        if self.verbose:
            HTTPConnection.debuglevel = 1
            requests_log = requests.packages.urllib3.add_stderr_logger()
        
        # Initial reconnaissance
        self.check_robots_txt()
        self.detect_tech_stack()
        self.enumerate_subdomains()
        self.check_load_balancers()
    
    def load_vulnerability_signatures(self):
        """Load vulnerability signatures from database"""
        try:
            with open(SIGNATURE_DB) as f:
                return json.load(f)
        except:
            return {
                "sql_errors": ["SQL syntax", "mysql_fetch", "syntax error", "unclosed quotation mark"],
                "xss_patterns": ["<script>alert", "onerror=", "javascript:"],
                "lfi_patterns": ["root:", "[boot loader]", "<?php"],
                "rfi_patterns": ["Example Domain", "Test Page for Apache"],
                "cmd_injection": ["uid=", "gid=", "Microsoft Windows", "Linux"],
                "ssrf_patterns": ["AMI ID", "instance-id", "SecretAccessKey"],
                "api_keys": ["AKIA[0-9A-Z]{16}", "sk_live_[0-9a-zA-Z]{24}", "AIza[0-9A-Za-z\\-_]{35}"]
            }
    
    def normalize_url(self, url):
        """Ensure URL has proper scheme and format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url  # Default to HTTPS
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(parsed._replace(path=parsed.path.rstrip('/')))
    
    def check_robots_txt(self):
        """Check and parse robots.txt with enhanced analysis"""
        robots_url = urllib.parse.urljoin(self.target_url, '/robots.txt')
        try:
            self.robots_parser.set_url(robots_url)
            self.robots_parser.read()
            
            # Additional analysis of robots.txt
            response = self.make_request(robots_url)
            if response:
                # Check for interesting entries
                interesting_paths = ['admin', 'backup', 'config', 'database', 'secret']
                for line in response.text.split('\n'):
                    if any(path in line.lower() for path in interesting_paths):
                        self.log_vulnerability(
                            "Information Disclosure",
                            robots_url,
                            f"Interesting path in robots.txt: {line.strip()}",
                            None
                        )
                
                if self.verbose:
                    print(f"[*] Found and analyzed robots.txt at {robots_url}")
        except Exception as e:
            if self.verbose:
                print(f"[!] Could not parse robots.txt: {e}")
    
    def is_allowed(self, url):
        """Check if URL is allowed by robots.txt with additional checks"""
        if not self.robots_parser.can_fetch(USER_AGENTS[0], url):
            return False
        
        # Additional checks for sensitive paths
        sensitive_keywords = ['admin', 'config', 'backup', 'wp-admin', 'phpmyadmin']
        if any(keyword in url.lower() for keyword in sensitive_keywords):
            if self.verbose:
                print(f"[*] Scanning sensitive path: {url}")
            return True  # We still want to scan these but note them
            
        return True
    
    def log_vulnerability(self, category, url, description, payload=None, severity="Medium"):
        """Record found vulnerability with enhanced details"""
        vuln = {
            'category': category,
            'url': url,
            'description': description,
            'payload': payload,
            'severity': severity,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'tech_stack': self.tech_stack.get(url, self.tech_stack.get(self.target_url, "Unknown"))
        }
        self.vulnerabilities.append(vuln)
        
        output = f"\n[!] {severity.upper()} {category.upper()} found at {url}\n"
        output += f"Description: {description}\n"
        if payload:
            output += f"Payload: {payload}\n"
        output += f"Technology: {vuln['tech_stack']}\n"
        output += "-" * 80 + "\n"
        
        print(output)
        
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(output)
    
    def make_request(self, url, method='GET', params=None, data=None, headers=None, allow_redirects=True):
        """Enhanced HTTP request with better error handling and fingerprinting"""
        if not self.is_allowed(url):
            if self.verbose:
                print(f"[!] Skipping {url} - disallowed by robots.txt")
            return None
            
        # Rotate user agent
        headers = headers or {}
        headers['User-Agent'] = random.choice(USER_AGENTS)

        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=TIMEOUT,
                    allow_redirects=allow_redirects,
                    stream=True
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    headers=headers,
                    timeout=TIMEOUT,
                    allow_redirects=allow_redirects
                )
            elif method.upper() == 'HEAD':
                response = self.session.head(
                    url,
                    headers=headers,
                    timeout=TIMEOUT,
                    allow_redirects=allow_redirects
                )
            else:
                return None

            # Store cookies for session analysis
            self.cookies.update(self.session.cookies.get_dict())
            return response
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[!] Request failed to {url}: {e}")
            return None

    def scan(self):
        """Main scanning function with enhanced workflow"""
        print(f"\n[*] Starting comprehensive scan of {self.target_url}")
        print(f"[*] Detected technologies: {json.dumps(self.tech_stack, indent=2)}")
        
        # Enhanced scanning workflow
        scan_steps = [
            self.crawl_site,
            self.check_sql_injection,
            self.check_xss,
            self.check_directory_traversal,
            self.check_command_injection,
            self.check_file_inclusion,
            self.check_ssrf,
            self.check_idor,
            self.check_cors_misconfig,
            self.check_security_headers,
            self.check_sensitive_files,
            self.check_jwt_issues,
            self.check_graphql_vulnerabilities,
            self.check_xxe,
            self.check_deserialization,
            self.check_http_request_smuggling,
            self.check_cache_poisoning,
            self.check_prototype_pollution,
            self.check_websockets
        ]
        
        if self.intensive:
            scan_steps.extend([
                self.brute_force_params,
                self.check_auth_bypass,
                self.check_2fa_bypass,
                self.check_oauth_flaws
            ])
        
        # Thread pool with progress tracking
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(step): step.__name__ for step in scan_steps}
            
            for future in as_completed(futures):
                step_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error in {step_name}: {e}")
                time.sleep(REQUEST_DELAY)
        
        # Post-scan analysis
        self.analyze_results()
        
        print("\n[*] Scan completed!")
        print(f"[*] Found {len(self.vulnerabilities)} potential vulnerabilities")
        
        if self.output_file:
            print(f"[*] Results saved to {self.output_file}")

    # Placeholder methods for the scan steps
    def crawl_site(self): pass
    def check_sql_injection(self): pass
    def check_xss(self): pass
    def check_directory_traversal(self): pass
    def check_command_injection(self): pass
    def check_file_inclusion(self): pass
    def check_ssrf(self): pass
    def check_idor(self): pass
    def check_cors_misconfig(self): pass
    def check_security_headers(self): pass
    def check_sensitive_files(self): pass
    def check_jwt_issues(self): pass
    def check_graphql_vulnerabilities(self): pass
    def check_xxe(self): pass
    def check_deserialization(self): pass
    def check_http_request_smuggling(self): pass
    def check_cache_poisoning(self): pass
    def check_prototype_pollution(self): pass
    def check_websockets(self): pass
    def brute_force_params(self): pass
    def check_auth_bypass(self): pass
    def check_2fa_bypass(self): pass
    def check_oauth_flaws(self): pass
    def detect_tech_stack(self): pass
    def enumerate_subdomains(self): pass
    def check_load_balancers(self): pass
    def analyze_results(self): pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ethical Web Vulnerability Scanner Pro")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-i", "--intensive", action="store_true", help="Run intensive scans")
    
    args = parser.parse_args()
    
    scanner = VulnerabilityScannerPro(
        target_url=args.target,
        output_file=args.output,
        verbose=args.verbose,
        intensive=args.intensive
    )
    scanner.scan()