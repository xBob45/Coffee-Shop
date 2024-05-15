## Coffee Shop

## Bachelor's Project Assignment


The primary goal of the bachelor's thesis is to create a demonstrably vulnerable environment in the form of a web application, which will allow for effective measurement and comparison of automated tools for penetration testing, vulnerability scanning, and static security analysis of source code. The web application will include vulnerabilities from all categories of the OWASP Top 10 list, with each vulnerability labeled and sufficiently documented. As part of the bachelor's thesis, a benchmarking exercise will be conducted on selected tools using the created vulnerable application.


## Requirements
- Docker
- Python
- PyYAML

## Usage
1. Open **vulnerabilities.yaml** and set vulnerabilities: 
   * Set to True to enable a vulnerability.
   * Set to False to fix a vulnerability.
   * Set to null to skip the vulnerability.
2. Run the **code_generation.py** script
3. Run **docker compose up -d**
4. Visit the http://127.0.0.1:9090 or https://127.0.0.1:9090 if you chose to use HTTPS. 
   * If using HTTPS, you must import the security certificate found in the /ssl folder. The method for importing a certificate may vary depending on the browser.

## Warning
- Application has been tested with Chrome 124.0.6367.119, Python 3.10.10 and PyYAML 6.0.1.
- Do **not** run the application in Incognito Mode, as it will prevent certain cookie-based attacks from being carried out.