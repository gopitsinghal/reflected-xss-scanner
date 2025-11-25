# Reflected XSS Scanner

A Python-based reflected XSS scanner that:

- Takes a target URL and a list of parameters.
- Generates context-aware XSS payloads via a `PayloadGenerator` class.
- Injects payloads in different positions/contexts (attribute name, attribute value, text node, script, event handler, tag-breaking, URL).
- Supports both GET and POST requests (including JSON bodies).
- Detects reflections via unique markers and simple HTML/response analysis.
- Produces terminal output and an HTML report, with optional JSON report.

---

## Assumptions

Since the spec is intentionally sparse, I made the following assumptions:

1. **Reflected XSS scope only**  
   The tool focuses on *reflected* XSS, not stored or DOM-only XSS. Detection is done purely on the HTTP response body.

2. **No JavaScript execution / browser engine**  
   The scanner does not spin up a browser. It inspects raw HTML/JSON text using string searches plus basic HTML parsing heuristics. Confirmation of “real” exploitability is out of scope.

3. **Parameter model**  
   - The scanner is given a list of **parameter names** (`-p q,search,category`) and assumes:
     - For GET: they appear as query string parameters.
     - For POST form: they are form fields.
     - For POST JSON: they are JSON keys.
   - For the **attribute-name** context, it is acceptable to inject payloads as parameter **names** (e.g., `?XSS_PARAM=1`) since some backends may reflect param names into HTML attributes or templates.

4. **Response handling**  
   - HTML pages are detected via `Content-Type` containing `text/html`.
   - JSON APIs are detected via `application/json`.
   - Everything else is treated as generic text (`raw-body`).

5. **Context classification is heuristic**  
   Because we don’t have full DOM execution, context classification (attribute name, value, text node, script, event-handler, etc.) is best-effort and meant to help triage, not be perfect.

6. **Authentication & headers**  
   - Authentication is represented via:
     - `--auth-bearer` for a simple Bearer token.
     - Optional custom headers and cookies.
   - More complex login flows (CSRF tokens, multi-step login) are not handled automatically.

---

## How the `PayloadGenerator` Chooses Payloads by Context

The `PayloadGenerator` class is responsible for generating payloads tailored to different **injection positions**. It exposes:

python
class PayloadGenerator:
    def generate(self, position: str) -> List[PayloadInstance]:

    

1. Marker Strategy
Each payload uses a placeholder {MARK} in its template (e.g. "<img src=x onerror=alert('{MARK}')>").

When generating payloads:
A unique marker is created per payload instance: e.g. XSS_ABC123_DE45.
The marker is substituted into the template, and we keep:
the final payload string,
the marker itself (for detection),
the position for later reporting.

Example marker usage:
Template: "</script><script>console.log('{MARK}')</script>"
Marker: XSS_ABC123_DE45
Payload: "</script><script>console.log('XSS_ABC123_DE45')</script>"

This lets the scanner detect reflections even if other characters are escaped or transformed.

2. Positions / Contexts Supported
The generator supports at least these positions (more than the required 3):
attr_name – intended for attribute-name injection:
Examples:
{MARK}
data-{MARK}
onmouseover{MARK}
{MARK}="1"

When scanning this position, the tool can inject payloads as parameter names (e.g. ?XSS_...=1) so they might be reflected in attribute names in server-side templates.
attr_value – intended for attribute values:

Examples:
{MARK}
"{MARK}"
'{MARK}'
{MARK}" onmouseover="alert(1)"
{MARK}><script>alert('{MARK}')</script>
text – intended for text nodes outside of tags:
Examples:
{MARK}
<img src=x onerror=alert('{MARK}')>
<svg/onload=alert('{MARK}')>
</script><script>console.log('{MARK}')</script>
script – intended for JavaScript context inside <script> tags:

Examples:
console.log('{MARK}');
');alert('{MARK}');//
");/*{MARK}*/
var x='{MARK}';
event – intended for event-handler attributes:

Examples:
alert('{MARK}')
console.log('{MARK}')
confirm('{MARK}')
tag_break – payloads that try to break out of existing tags:

Examples:
"><script>alert('{MARK}')</script>
'><img src=1 onerror=console.log('{MARK}')>
></textarea><script>console.log('{MARK}')</script>
url – for places where parameters may end up in URLs:

Examples:
javascript:alert('{MARK}')
https://example.com/?q={MARK}
The scanner can be restricted to specific positions via --positions, for example:



--positions "attr_name,attr_value,text,script"
Reflection Detection Approach
Reflection detection happens in two steps:

Marker Presence Check

Each request sends a payload with a unique marker string.

The response body is scanned for that marker (not the raw payload), using a simple substring search.

If the marker does not appear, we consider the test non-reflected.

Context Classification (Heuristic)

If marker is present, the scanner tries to classify likely contexts:

It inspects Content-Type:

text/html → parse as HTML using BeautifulSoup.

application/json → classify as json-value.

Other types → classify as raw-body.

For text/html, we use BeautifulSoup to find:

Script context
If the marker appears inside <script> tag text → context script.

Tag name
If marker appears in tag.name → context tag-name.

Attribute name
If marker appears in any attribute key → context attribute-name.

Attribute value
If marker appears in attribute value:

If attribute name starts with on → context event-handler.

Else → context attribute-value.

Text node
If marker appears in a text node (NavigableString) outside tags → context text-node.

If nothing conclusive is found, we fall back to unknown.

These contexts are reported per finding, for example:

text

Contexts: script, attribute-value
Setup / Run Steps
1. Install Dependencies
```
pip install -r requirements.txt
or
pip install requests beautifulsoup4
```

2. Basic Usage
```
GET scan
python advanced_xss_scanner.py \
  -u "https://example.com/search" \
  -p "q,category" \
  -X GET
POST form scan


python advanced_xss_scanner.py \
  -u "https://example.com/login" \
  -p "username,password" \
  -X POST
POST JSON body scan


python advanced_xss_scanner.py \
  -u "https://api.example.com/search" \
  -p "query" \
  -X POST \
  --json-body
```

3. Custom headers, cookies, auth, proxy
```
python advanced_xss_scanner.py \
  -u "https://target.com/app" \
  -p "q" \
  -X GET \
  --headers "User-Agent:MyScanner,Accept:text/html" \
  --cookies "session:abcd1234" \
  --auth-bearer "YOUR_BEARER_TOKEN" \
  --proxy "http://127.0.0.1:8080" \
  --no-verify-ssl
```

4. Positions and performance tuning
```
python advanced_xss_scanner.py \
  -u "https://target.com/search" \
  -p "q" \
  -X GET \
  --positions "attr_name,attr_value,text,script" \
  --threads 20 \
  --delay 0.05
```

5. Reports

Terminal summary: always printed.
HTML report: --html-report xss_report.html (default name if not changed).
JSON report (optional):

```
python advanced_xss_scanner.py \
  -u "https://target.com/search" \
  -p "q" \
  -X GET \
  --json-report xss_report.json
```
Terminal Output:
The scanner always prints a summary to the terminal, including:
UR
HTTP method
Parameter
Position (context tested)
Injection mode (name/value)
Status code
Content-Type
Marker
Payload
Detected contexts

