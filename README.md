# PhishGuard
# PhishGuard - Phishing Website Detection Tool

PhishGuard is a simple Python-based tool designed to detect phishing websites by analyzing URLs and checking for various signs of phishing. This tool inspects different factors like HTTPS status, domain age, suspicious patterns in the URL, and HTTP security headers to determine whether a website is safe or potentially malicious.

## Features

- **HTTPS Check**: Ensures the website uses HTTPS for secure communication.
- **Domain Age Check**: Verifies the registration date of the domain to check for newly created domains (common with phishing sites).
- **Suspicious URL Patterns**: Scans for phishing-related keywords like "login", "secure", etc.
- **HTTP Header Check**: Verifies whether important security headers like **Strict-Transport-Security** are present.

## Installation

1. **Clone the repository** to your local machine:
    ```bash
    git clone https://github.com/yourusername/phishguard.git
    cd phishguard
    ```

2. **Install the required Python libraries**:
    ```bash
    pip install -r requirements.txt
    ```

## Requirements

- Python 3.x
- The following libraries:
  - `requests`
  - `whois`
  - `tldextract`
  - `beautifulsoup4`
  - `regex`

These dependencies are automatically listed in the `requirements.txt` file, which you can install using `pip`.

## Usage

1. **Run the script** by entering the following command in your terminal:
    ```bash
    python phishing_detector.py
    ```

2. **Input the URL** you want to check when prompted:
    ```bash
    Enter URL to check: https://example.com
    ```

3. The script will output the result, telling you whether the site is potentially phishing or safe:
    - **"Phishing: No HTTPS"**: The site doesn't use HTTPS.
    - **"Phishing: New Domain"**: The domain is newly registered.
    - **"Phishing: Suspicious URL"**: The URL contains phishing-related keywords.
    - **"Phishing: Missing Security Headers"**: The site lacks important security headers.
    - **"This website seems safe!"**: The site is not a phishing site.

## Example Output

```bash
Enter URL to check: http://example.com
[!] Warning: http://example.com does not use HTTPS.
Detection Result: Phishing: No HTTPS
