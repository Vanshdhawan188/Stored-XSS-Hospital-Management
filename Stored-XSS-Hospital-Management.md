# Stored XSS Vulnerability in Hospital Management System v4.0

## Vulnerability Summary

A critical **Stored Cross-Site Scripting (XSS)** vulnerability was discovered in the `edit-patient.php` file of **PHPGurukul's Hospital Management System (v4.0)**.  
Attackers can inject malicious JavaScript via the `patname` field (POST parameter), which gets **persistently stored in the database** and executed whenever the profile page is viewed.

## Key Details

| Property             | Value                                                                 |
|----------------------|------------------------------------------------------------------------|
| **Affected Vendor**  | PHPGurukul                                                              |
| **Vulnerable File**  | `edit-profile.php`                                                     |
| **Attack Vector**    | `patname` parameter via POST request                                   |
| **Vulnerability Type** | Stored Cross-Site Scripting (XSS)                                   |
| **Version Affected** | v4.0                                                                   |
| **Official Website** | [Hospital Management System](https://phpgurukul.com/online-hospital-management-system-using-php-mysql/) |

## Proof of Concept (PoC)

### Step 1: Login to the Hospital Management System

Navigate to the login portal and authenticate using valid credentials.

```
http://192.168.137.97/hospital/hms/doctor/
```

![Login Page](https://github.com/user-attachments/assets/f93011f2-19a0-4f24-ba32-fec49ac9f3c1)

---

### Step 2: Inject XSS Payload in Name Field

Navigate to Edit Profile section:

```
http://192.168.137.97/hospital/hms/doctor/manage-patient.php
```

Paste the following payload in the "Doctor Name" input field and click Update:

```html
zlqd9<script>alert(1)</script>w6dg0
```

![Payload Injection](https://github.com/user-attachments/assets/12760121-35b4-4639-8a9e-de71e9f0d725)

---

### Step 3: Trigger the Payload

Reload the profile page.  
You’ll see a JavaScript `alert(1)` triggered — confirming the stored XSS vulnerability.

Also, refreshing the page again will show the alert repeatedly.

![Alert 1](https://github.com/user-attachments/assets/359d6f6b-119b-480f-9a12-22b041ba89f5)  
![Alert 2](https://github.com/user-attachments/assets/add1e779-662c-4b10-b401-8c6d7510074a)

---

## Potential Impact

- **Session Hijacking** – Steal user/admin session cookies via `document.cookie`.
- **Phishing** – Inject fake forms to harvest credentials.
- **Defacement** – Alter webpage content, defame the brand.
- **Data Exfiltration** – Steal sensitive data through background requests.
- **Malware Propagation** – Redirect users to malicious domains.
- **Privilege Escalation** – Gain access to higher-privilege accounts by exploiting stored scripts.

---

## Mitigation Strategies

### Input Sanitization

Sanitize all user inputs on the server side using:

```php
htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```

### Output Encoding

Encode output before rendering dynamic content:

```php
echo htmlentities($user_input, ENT_QUOTES, 'UTF-8');
```

### Content Security Policy (CSP)

Implement a strong CSP header to prevent inline script execution:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
```

### Use Modern Frameworks

Use frameworks like Laravel, Symfony, or CodeIgniter, which offer built-in XSS protection.

### Security Testing

Perform regular penetration testing using tools such as:

- OWASP ZAP
- Burp Suite

---

## References and Resources

- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/xss-prevention)
- [Content Security Policy (CSP) Guide - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [PHP htmlspecialchars()](https://www.php.net/manual/en/function.htmlspecialchars.php)
- [PHPGurukul Hospital Management System](https://phpgurukul.com/online-hospital-management-system-using-php-mysql/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)

---

**Author:** Subhash Paudel  
**Date:** 2025-06-02  
**Severity:** High
