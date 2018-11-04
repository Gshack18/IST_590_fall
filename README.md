# IST_590_fall
# this is for IST 590 class


# Project 7 - WordPress Pentesting

Time spent: 9 hours spent in total

> Objective: Find, analyze, recreate, and document **five vulnerabilities** affecting an old version of WordPress
Table of Contents

Summary
List of Vulnerabilities found

-[!] Title: WordPress 4.2-4.7.2 - Press This CSRF DoS

-[!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset

-[!] Title: WordPress 2.5-4.6 - Authenticated Stored Cross-Site Scripting via Image Filename

-[!] Title: WordPress <= 4.3 - User List Table Cross-Site Scripting (XSS)


## Pentesting Report

1.  Press This CSRF DoS or CVE-2017-6814 
 
Summary
A vulnerability is when something gets exposed by being attacked like in this case Word Press. As with open source software such as Word Press it leaves the doors open to the public who can then try to expose the critical flaws it has. For IST 590 I couldn’t get the virtual machine to build with “vagrant up” command even though I had it installed with the plug in so I was tasked with finding vulnerabilities from a WPS scan. 

1. Press This CSRF DoS named CVE-2017-6814 is a cross site request forgery that occurs within the “press this page” on WordPress with allows the occurance of publishing with a bookmarklet so an admin can quickly reach their admin page to edit the WordPress documents. 

Walkthrough
This can be done by doing a denial of service attack when the admin goes to a malicious webpage by inserting a get request from the server with a /wp-admin/press-this.php?u=<URL>&url-scan-submit=Scan. 
This vulnerability was founded during a summer of pwnage even by a group who call themselves bughunters in Amsterdam. 

Fix 
Install WordPress version 4.7.3 or higher
https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/



2. (Required) Vulnerability Name or ID
  - [ ] Summary: 
    - Vulnerability types:
    - Tested in version:
    - Fixed in version: 
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)
1. (Required) Vulnerability Name or ID
  - [ ] Summary: 
    - Vulnerability types:
    - Tested in version:
    - Fixed in version: 
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)
1. (Optional) Vulnerability Name or ID
  - [ ] Summary: 
    - Vulnerability types:
    - Tested in version:
    - Fixed in version: 
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)
1. (Optional) Vulnerability Name or ID
  - [ ] Summary: 
    - Vulnerability types:
    - Tested in version:
    - Fixed in version: 
  - [ ] GIF Walkthrough: 
  - [ ] Steps to recreate: 
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php) 

## Assets

List any additional assets, such as scripts or files

## Resources

- [WordPress Source Browser](https://core.trac.wordpress.org/browser/)
- [WordPress Developer Reference](https://developer.wordpress.org/reference/)

GIFs created with [LiceCap](http://www.cockos.com/licecap/).

## Notes

Describe any challenges encountered while doing the work

## License

    Copyright [yyyy] [name of copyright owner]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
