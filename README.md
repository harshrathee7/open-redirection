### **Open Redirection Vulnerability** 
Open Redirect is a web security vulnerability where an application allows unvalidated or uncontrolled redirections to external URLs. Attackers exploit this to redirect users to malicious websites, often for phishing, malware distribution, or bypassing security controls.
---

## How Open Redirect Works  
An application may use a URL parameter to control navigation, such as:  

  **Vulnerable Example:**  
```plaintext
https://example.com/redirect.php?url=http://malicious.com
```
If the website **does not validate** the `url` parameter, an attacker can modify it to redirect users to a phishing or malware site.

  **Example in PHP (Vulnerable Code)**  
```php
<?php
$url = $_GET['url'];
header("Location: $url"); // 🚨 No validation, vulnerable to Open Redirect!
exit();
?>
```

---

## ** Exploitation of Open Redirect**
### ** 1. Phishing Attacks**
- Attackers send fake emails with trusted domain names but use redirection to a malicious login page.  
- Example:  
  ```plaintext
  https://trusted-bank.com/login?next=http://evil.com/fake-login
  ```

### ** 2. Bypassing Security Controls**
- Some security filters block direct access to malicious websites, but an open redirect can bypass them.
- Example:
  ```plaintext
  https://example.com/redirect?url=http://malicious.com
  ```
  - The victim trusts `example.com`, clicks the link, and gets redirected to `malicious.com`.

### ** 3. Exploiting OAuth & Single Sign-On (SSO)**
- Open redirects in authentication flows allow attackers to steal OAuth tokens.
- Example:
  ```
  https://trusted-site.com/auth?redirect_uri=http://attacker.com
  ```

---

## ** Preventing Open Redirect Vulnerabilities**
###  **1. Whitelist Allowed Domains**
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

###  **2. Use Relative URLs Instead of Full URLs**
- Avoid allowing external redirections.
- Example:
  ```
  https://example.com/redirect.php?url=/dashboard
  ```
  - Redirect only within `example.com`.

###  **3. Encode & Validate Input**
- Check if the URL belongs to your domain before redirecting.
- Example:
  ```php
  if (!preg_match('/^https:\/\/trusted-site\.com/', $_GET['url'])) {
      die("Invalid redirect URL!");
  }
  ```

###  **4. Implement Security Headers**
- Use `X-Frame-Options` and `Referrer-Policy` to prevent abuse.

---

## **4️ Detecting Open Redirects in Web Applications**
### ** Manual Testing**
1. Identify URL parameters handling redirection (`url`, `next`, `redirect`).  
2. Test with different values:
   ```
   https://example.com/redirect.php?url=https://evil.com
   ```
3. If it redirects, it's vulnerable.

### **🔧 Automated Tools**
- **Burp Suite**: Use "Open Redirect" scanner.
- **Nuclei**: Run Open Redirect templates:
  ```sh
  nuclei -t http/open-redirect.yaml -u https://example.com
  ```
- **Google Dorking**:
  ```
  inurl:"redirect.php?url="
  ```

---

## ** Real-World Open Redirect Exploits**
###  **1. PayPal Open Redirect (2014)**
- Attackers used PayPal's redirection feature to phish users.
- Users received emails with:
  ```
  https://www.paypal.com/cgi-bin/webscr?cmd=_hosted-payment&redirect=http://evil.com
  ```

###  **2. Google Open Redirect**
- Found in Google's OAuth login process.
- Attackers used it to steal authentication tokens.

---

## **Conclusion**
🔹 Open Redirect vulnerabilities are **often ignored but dangerous**.  
🔹 Attackers exploit them for **phishing, security bypasses, and OAuth token theft**.  
🔹 **Always validate URLs** before redirection to prevent abuse.  

---
