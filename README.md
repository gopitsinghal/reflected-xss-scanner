#Advanced Reflected XSS Scanner
A lightweight, multi-threaded vulnerability scanner written in Python designed to detect Reflected Cross-Site Scripting (XSS) vulnerabilities.
Unlike basic scanners that simply look for a payload reflection, this tool uses Context-Aware Detection—combining Regex heuristics and HTML parsing (BeautifulSoup)—to intelligently determine if a payload has successfully broken out of an HTML tag, attribute, or script context.
🚀 Features
Smart Context Detection: Distinguishes between reflections in raw text, HTML attributes, and script tags.
Hybrid Analysis: Uses a combination of Regex (for broken HTML) and BeautifulSoup (for structured parsing) to minimize false negatives.
Unique Markers: Generates random tokens (e.g., XSS_A1B2) for every payload to prevent false positives from previous requests.
Multi-Method Support: Supports both GET (URL parameters) and POST (Form data) requests.
Polyglot Payloads: Includes complex payload chains designed to break out of multiple contexts simultaneously.
Multi-Threading: Uses ThreadPoolExecutor for rapid parallel scanning.
⚙️ Installation
Clone the repository:
git clone [https://github.com/yourusername/xss-scanner.git](https://github.com/yourusername/xss-scanner.git)
cd xss-scanner


Install dependencies:
This tool requires requests for HTTP handling and beautifulsoup4 for HTML parsing.
pip install -r requirements.txt

If you don't have a requirements file yet, simply run:
pip install requests beautifulsoup4


🛠️ Usage
The script is run from the command line. You must specify the target URL and the parameters you wish to test.
Basic Command Structure
python3 xss_scanner.py -u <TARGET_URL> -p <PARAMS> [OPTIONS]


Arguments
Flag
Long Flag
Description
Required
Default
-u
--url
The full target URL (e.g., http://site.com/search.php).
✅ Yes
N/A
-p
--params
Comma-separated list of parameters to test (e.g., q,id).
✅ Yes
N/A
-m
--method
HTTP Method to use (GET or POST).
❌ No
GET
-t
--threads
Number of concurrent threads to run.
❌ No
5
-h
--help
Show the help message and exit.
❌ No
N/A

💡 Examples
1. Basic GET Scan (Search Bar)
Scans the q parameter on a search page.
python3 xss_scanner.py -u [http://testphp.vulnweb.com/listproducts.php](http://testphp.vulnweb.com/listproducts.php) -p cat


2. Scanning Multiple Parameters
Scans both the query and sort parameters simultaneously.
python3 xss_scanner.py -u [http://example.com/search](http://example.com/search) -p query,sort


3. POST Request (Login Forms)
Scans a login form where data is sent in the HTTP body.
python3 xss_scanner.py -u [http://testphp.vulnweb.com/userinfo.php](http://testphp.vulnweb.com/userinfo.php) -p uname,pass -m POST


4. High-Speed Scan
Increases the number of worker threads to 10 for faster results.
python3 xss_scanner.py -u [http://example.com/search](http://example.com/search) -p q -t 10


🧠 How It Works
Payload Generation: The tool generates a specific malicious string containing a unique random ID (the Marker).
Injection: It injects this payload into the specified parameter via GET or POST.
Reflection Check: It downloads the response and checks if the unique Marker exists in the raw text.
Context Analysis:
If the marker is found, the Robust Context Detector kicks in.
It checks if the payload landed inside a <script> tag, an HTML attribute (like href="..."), or plain HTML text.
It verifies if the HTML syntax was successfully broken (e.g., breaking out of a value="..." attribute).
⚠️ Legal Disclaimer
Usage of this program is strictly for educational purposes and for testing websites you own or have explicit permission to test.
Scanning targets without authorization is illegal and punishable by law. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
Do not use this tool on government websites.
Do not use this tool on financial institutions without a contract.
Always obtain written permission (Scope of Work) before scanning.
🤝 Contributing
Contributions are welcome! Please follow these steps:
Fork the project.
Create your feature branch (git checkout -b feature/AmazingFeature).
Commit your changes (git commit -m 'Add some AmazingFeature').
Push to the branch (git push origin feature/AmazingFeature).
Open a Pull Request.
📝 License
Distributed under the MIT License. See LICENSE for more information.
