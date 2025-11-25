# 🛡️ Advanced Reflected XSS Scanner

**A lightweight, multi-threaded vulnerability scanner written in Python designed to detect Reflected Cross-Site Scripting (XSS) vulnerabilities.**

Unlike basic scanners that simply look for a payload reflection, this tool uses **Context-Aware Detection**—combining Regex heuristics and HTML parsing (`BeautifulSoup`)—to intelligently determine if a payload has successfully broken out of an HTML tag, attribute, or script context.

---

## 🚀 Features

* **Smart Context Detection:** Distinguishes between reflections in raw text, HTML attributes, and script tags.
* **Hybrid Analysis:** Uses a combination of Regex (for broken HTML) and BeautifulSoup (for structured parsing) to minimize false negatives.
* **Unique Markers:** Generates random tokens (e.g., `XSS_A1B2`) for every payload to prevent false positives from previous requests.
* **Multi-Method Support:** Supports both **GET** (URL parameters) and **POST** (Form data) requests.
* **Polyglot Payloads:** Includes complex payload chains designed to break out of multiple contexts simultaneously.
* **Multi-Threading:** Uses `ThreadPoolExecutor` for rapid parallel scanning.

---

## ⚙️ Installation

### 1. Clone the repository
```
git clone [https://github.com/yourusername/xss-scanner.git](https://github.com/yourusername/xss-scanner.git)
cd xss-scanner
```
2. Install dependencies
   This tool requires requests for HTTP handling and beautifulsoup4 for HTML parsing.
```
   pip install -r requirements.txt
```
If you do not have a requirements file yet, simply run:
```
pip install requests beautifulsoup4
```

🛠️ Usage
The script is run from the command line. You must specify the target URL and the parameters you wish to test.
Basic Command Structure
```
python3 xss_scanner.py -u <TARGET_URL> -p <PARAMS> [OPTIONS]
```
Arguments
### Arguments

| Flag | Long Flag | Description | Required | Default |
| :--- | :--- | :--- | :---: | :---: |
| `-u` | `--url` | The full target URL (e.g., `http://site.com/search.php`). | ✅ Yes | N/A |
| `-p` | `--params` | Comma-separated list of parameters to test (e.g., `q,id`). | ✅ Yes | N/A |
| `-m` | `--method` | HTTP Method to use (`GET` or `POST`). | ❌ No | `GET` |
| `-t` | `--threads`| Number of concurrent threads to run. | ❌ No | `5` |
| `-h` | `--help` | Show the help message and exit. | ❌ No | N/A |

## 💡 Examples

Here are the most common usage scenarios. You can run these commands from your terminal.

1. Basic GET Scan (Search Bar)
Scans the q parameter on a search page.
```
python3 xss_scanner.py -u [http://testphp.vulnweb.com/listproducts.php](http://testphp.vulnweb.com/listproducts.php) -p cat
```

2. Scanning Multiple Parameters
Scans both the query and sort parameters simultaneously.
```
python3 xss_scanner.py -u [http://example.com/search](http://example.com/search) -p query,sort
```

3. POST Request (Login Forms)
Scans a login form where data is sent in the HTTP body.
```
python3 xss_scanner.py -u [http://testphp.vulnweb.com/userinfo.php](http://testphp.vulnweb.com/userinfo.php) -p uname,pass -m POST
```

4. High-Speed Scan
Increases the number of worker threads to 10 for faster results.
```
python3 xss_scanner.py -u [http://example.com/search](http://example.com/search) -p q -t 10
```

## 🧠 How It Works

The scanner follows a strict four-step logic pipeline to ensure accuracy and minimize false positives.

1.  **Payload Generation & Tokenization**
    * Instead of sending static strings, the engine generates a **Unique Random Marker** (e.g., `XSS_4f9a`) for every single request.
    * This prevents the scanner from mistaking previous error messages or cached pages for a successful reflection.

2.  **Injection & Transport**
    * The tool injects the payload into the target parameters using the specified method (**GET** or **POST**).
    * It uses `ThreadPoolExecutor` to handle multiple parameters or payloads concurrently.

3.  **Reflection Analysis**
    * The response is analyzed to see if the Unique Marker exists in the raw HTML body.
    * If the marker is **not found**, the parameter is deemed safe (or filtered).

4.  **Context-Aware Heuristics (The "Smart" Engine)**
    * If the marker **is found**, the tool parses the HTML context around it using `BeautifulSoup`.
    * **HTML Text Context:** Checks if the payload was rendered as raw text (safe) or executable HTML.
    * **Attribute Context:** Checks if the payload is trapped inside an attribute (e.g., `value="PAYLOAD"`) and if it successfully broke out (e.g., `value="" onload=alert(1)`).
    * **Script Context:** Checks if the input landed inside a `<script>` tag and if the JavaScript syntax was disrupted.


## ⚠️ Legal Disclaimer

> **This tool is created for educational purposes only and for the testing of websites you own or have explicit permission to test.**

**Usage of this program for attacking targets without prior mutual consent is illegal.** It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### Rules of Engagement:
* ❌ **Do not** use this tool on government websites.
* ❌ **Do not** use this tool on financial institutions without a signed contract.
* ✅ **Always** obtain written permission (Scope of Work) from the target owner before running a scan.

---

## 🤝 Contributing

Contributions are always welcome! If you have ideas for new payloads, smarter context detection, or optimization, please follow these steps:

1.  **Fork the Project**
    (Click the "Fork" button at the top right of this page)

2.  **Create your Feature Branch**
    ```
    git checkout -b feature/AmazingFeature
    ```

3.  **Commit your Changes**
    ```
    git commit -m 'Add some AmazingFeature'
    ```

4.  **Push to the Branch**
    ```
    git push origin feature/AmazingFeature
    ```

5.  **Open a Pull Request**
    (Go to the "Pull Requests" tab in your forked repository and click "New Pull Request")

