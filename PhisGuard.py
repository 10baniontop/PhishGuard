import tkinter as tk
from tkinter import ttk, messagebox
import requests
import whois
import tldextract
import datetime
from urllib.parse import urlparse


def check_https(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme == 'https'


def get_domain_info(url):
    domain = tldextract.extract(url).domain
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception:
        return None


def check_suspicious_patterns(url):
    suspicious_keywords = ["login", "signin", "secure", "update", "confirm"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return True
    return False


def check_headers(url):
    try:
        headers = requests.head(url, timeout=5).headers
        if 'Strict-Transport-Security' not in headers:
            return True
    except requests.RequestException:
        return True
    return False


def check_openphish(url):
    """
    Checks if the given URL is listed in OpenPhish's phishing database.
    """
    try:
        openphish_feed = requests.get("https://openphish.com/feed.txt", timeout=5).text
        phishing_sites = openphish_feed.split("\n")
        if url in phishing_sites:
            return True  # URL is phishing
    except requests.RequestException:
        return False  # Unable to check (e.g., no internet connection)
    return False  # URL not found in OpenPhish


def detect_phishing(url):
    if check_openphish(url):
        result_var.set(f"[!] Alert: {url} is listed as phishing in OpenPhish!")
        return "Phishing: OpenPhish"

    if not check_https(url):
        result_var.set(f"[!] Warning: {url} does not use HTTPS.")
        return "Phishing: No HTTPS"

    whois_info = get_domain_info(url)
    if whois_info and whois_info.creation_date:
        creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
        age = (datetime.datetime.now() - creation_date).days
        if age < 30:
            result_var.set(f"[!] Warning: {url} is a newly registered domain. Age: {age} days.")
            return "Phishing: New Domain"

    if check_suspicious_patterns(url):
        result_var.set(f"[!] Warning: {url} contains suspicious patterns.")
        return "Phishing: Suspicious URL"

    if check_headers(url):
        result_var.set(f"[!] Warning: {url} has potential issues with HTTP headers.")
        return "Phishing: Missing Security Headers"

    result_var.set(f"[+] {url} seems safe!")
    return "This website seems safe!"


def on_check_click():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Input Error", "Please enter a URL.")
        return
    result = detect_phishing(url)
    result_label.config(text=result)


def clear_text():
    url_entry.delete(0, tk.END)
    result_label.config(text="")


root = tk.Tk()
root.title("PhishGuard - Phishing Website Detection Tool")
root.geometry("400x250")
root.resizable(False, False)

ttk.Label(root, text="Enter URL to check:", font=("Arial", 12)).pack(pady=10)

url_entry = ttk.Entry(root, width=40, font=("Arial", 12))
url_entry.pack(pady=5)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

check_button = ttk.Button(button_frame, text="Check URL", command=on_check_click)
check_button.grid(row=0, column=0, padx=5)

clear_button = ttk.Button(button_frame, text="Clear", command=clear_text)
clear_button.grid(row=0, column=1, padx=5)

result_label = ttk.Label(root, text="", font=("Arial", 12), foreground="green")
result_label.pack(pady=10)

result_var = tk.StringVar()

root.mainloop()
