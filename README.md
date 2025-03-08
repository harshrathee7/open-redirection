### **Open Redirection Vulnerability**  

**Open Redirect** is a web security vulnerability where an application allows unvalidated or uncontrolled redirections to external URLs. Attackers exploit this to **redirect users to malicious websites**, often for phishing, malware distribution, or bypassing security controls.  

---

## How Open Redirect Works  
An application may use a URL parameter to control navigation, such as:  

  Vulnerable Example:  
```plaintext
https://insecure-web.com/redirect.php?url=http://malicious.com
```
If the website does not validate the `url` parameter, an attacker can modify it to redirect users to a phishing or malware site.

  **Example in PHP (Vulnerable Code)**  
```php
<?php
$url = $_GET['url'];
header("Location: $url"); // 🚨 No validation, vulnerable to Open Redirect!
exit();
?>
```

---

##  Exploitation of Open Redirect
###  1. Phishing Attacks
- Attackers send fake emails with trusted domain names but use redirection to a malicious login page.  
- Example:  
  ```plaintext
  https://trusted-bank.com/login?next=http://evil.com/fake-login
  ```

###  2. Bypassing Security Controls
- Some security filters block direct access to malicious websites, but an open redirect can bypass them.
- Example:
  ```plaintext
  https://example.com/redirect?url=http://malicious.com
  ```
  - The victim trusts `example.com`, clicks the link, and gets redirected to `malicious.com`.

###  3. Exploiting OAuth & Single Sign-On (SSO)
- Open redirects in authentication flows allow attackers to steal OAuth tokens.
- Example:
  ```
  https://trusted-site.com/auth?redirect_uri=http://attacker.com
  ```

---

##  Preventing Open Redirect Vulnerabilities
###  1. Whitelist Allowed Domains
- Only allow redirections to trusted domains.
- Example in PHP:
  ```php
  <?php
  $allowed_domains = ["example.com"];
  $url = parse_url($_GET['url'], PHP_URL_HOST);
  
  if (in_array($url, $allowed_domains)) {
      header("Location: " . $_GET['url']);
      exit();
  } else {
      die("Invalid redirect URL!");
  }
  ?>
  ```

###  2. Use Relative URLs Instead of Full URLs
- Avoid allowing external redirections.
- Example:
  ```
  https://example.com/redirect.php?url=/dashboard
  ```
  - Redirect only within `example.com`.

###  3. Encode & Validate Input
- Check if the URL belongs to your domain before redirecting.
- Example:
  ```php
  if (!preg_match('/^https:\/\/trusted-site\.com/', $_GET['url'])) {
      die("Invalid redirect URL!");
  }
  ```

###  4. Implement Security Headers
- Use `X-Frame-Options` and `Referrer-Policy` to prevent abuse.

---


## How to test open redirection vulnerability 

---

### 1. Manual Testing**  
You can manually test for open redirection by manipulating parameters in URLs that handle redirection.

#### Common Parameters
```
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```

#### Basic Payloads to Try 
Replace the URL parameter with an external malicious domain:  
- Example 1:
  ```
  https://example.com/login?next=http://evil.com
  ```
- Example 2:  
  ```
  https://example.com/redirect.php?url=https://evil.com
  ```

#### Bypassing Filtering Techniques  
If the application has some restrictions, try:  
- Using URL encoding:
  ```
  https://example.com/redirect.php?url=%68%74%74%70%3a%2f%2fevil.com
  ```
- Using `//` to force a redirect:  
  ```
  https://example.com/redirect.php?url=//evil.com
  ```
- Using nested redirects:
  ```
  https://example.com/redirect.php?url=https://trusted.com@evil.com
  ```

---

### 2. Automated Testing  
You can automate open redirection testing by combining **ParamSpider** (to find URL parameters) and **Oralyzer** (to test for open redirection).  

### Using ParamSpider to Gather URLs 
```bash
git clone https://github.com/devanshbatham/paramspider.git
cd paramspider
pip install -r requirements.txt
python3 paramspider.py --domain example.com
```

#### Using Oralyzer to Detect Open Redirects  
```bash
git clone https://github.com/r0075h3ll/Oralyzer.git
cd Oralyzer
pip install -r requirements.txt
python3 oralyzer.py -l urls.txt
```

Alternatively, you can use **Burp Suite Intruder** or **Nuclei** with an open redirection template.

---

### 3. Using Nuclei for Automated Scanning  
```bash
nuclei -u "https://example.com?redirect=evil.com" -t open-redirect.yaml
```
Get open redirect templates:  
```bash
nuclei -ut && nuclei -tl | grep redirect
```

---

### 4. Testing with Burp Suite
- **Use Burp Proxy** to intercept requests.  
- **Modify the redirect parameter** with an external domain.  
- **Check if it redirects to an external site** without validation.


---

###  Real-World Open Redirect Exploits
###  1. PayPal Open Redirect (2014)
- Attackers used PayPal's redirection feature to phish users.
- Users received emails with:
  ```
  https://www.paypal.com/cgi-bin/webscr?cmd=_hosted-payment&redirect=http://evil.com
  ```

###  2. Google Open Redirect
- Found in Google's OAuth login process.
- Attackers used it to steal authentication tokens.

---

### Mitigation
To prevent open redirection vulnerabilities:  
- Validate redirect URLs and allow only trusted domains.  
- Implement allowlists for redirects (e.g., same-origin policy).  
- Use relative URLs instead of full URLs for redirection.  
- Encode and sanitize user inputs properly.  



---
