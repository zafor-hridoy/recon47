**Project Assignment: Automated Reconnaissance & Vulnerability Scanner**

**Objective:** Develop a tool that automates reconnaissance and vulnerability scanning for web targets. The project should simulate a lightweight, real-world security assessment workflow.

**Project Requirements**

Your tool must:

* Accept a domain, subdomain, URL, or IP address as input.  
* Perform automated reconnaissance on the target.  
* Discover and collect attack surface information.  
* Crawl the target and collect URLs/endpoints.  
* Extract parameters and JavaScript files.  
* Perform vulnerability scanning.  
* Generate a structured report of the findings.

**Reconnaissance Requirements**

The tool should collect relevant information, such as:

* Subdomains  
* Open ports and services  
* Technologies and frameworks in use  
* HTTP headers  
* DNS information  
* JavaScript files  
* Interesting endpoints and directories  
* Parameters and forms

**Vulnerability Scanning Requirements**

The tool must include an automated vulnerability scanning capability. Students may choose to:

* Develop their own custom checks.  
* Integrate existing tools.  
* Combine both approaches.

The scanner should be capable of identifying common web security issues and organizing the findings properly. For the vulnerability scanning use nikto and nuclei. 

**Reporting Requirements**

The tool must generate a final report containing:

* Target information  
* Reconnaissance findings  
* Collected endpoints/URLs  
* Discovered technologies  
* Vulnerability findings  
* Severity or risk level of discovered vulnerabilities  
* Timestamp of the scan

**Technical Requirements**

* **Execution:** CLI-based execution is required.  
* **Architecture:** Modular architecture is highly preferred.  
* **Reliability:** Proper error handling is required to prevent crashes.  
* **Output:** Clean, organized, and readable console output is required.

**Bonus Features**

Additional credit will be awarded for implementing any of the following features:

* Recursive crawling  
* Multi-threading / asynchronous processing for speed  
* Smart filtering and deduplication of results  
* Dashboard / Graphical User Interface (GUI)  
* HTML report generation  
* Docker support (containerized application)  
* AI-assisted summarization of findings  
* Advanced attack surface discovery  
* Stealth or optimized scanning logic (e.g., rate-limiting, evasion)

**Restrictions (Strictly Enforced)**

* **Authorization:** Scan ONLY authorized targets (e.g., your own local VMs, dedicated test labs, or explicit bug bounty programs).  
* **No Destructive Exploitation:** Do not attempt to alter, delete, or destroy data.  
* **No Denial-of-Service (DoS):** Ensure your tool does not overwhelm the target server.  
* **Ethics:** Follow all ethical hacking practices and legal guidelines.

**Evaluation Criteria**

| Criteria | Marks |
| ----- | ----- |
| **Functionality** | 30 |
| **Recon Automation** | 25 |
| **Real-World Practicality** | 20 |
| **Code Quality** | 15 |
| **Reporting & Documentation** | 10 |
| **Total** | **100** |

## 

## **Submission Instructions**

Please follow these steps to submit your project:

1. **GitHub Repository:** Upload your entire project to a GitHub repository. Your repository must include:  
   * **Source Code:** Well-commented and organized.  
   * **Documentation/README.md:** Instructions on how to install dependencies and run the tool.  
   * **Sample Output/Report:** A generated report from a test scan.  
   * **Demo Video (optional for now):** A link to a short video demonstrating the tool's execution and features (this link can be included in your README file).  
2. **Google Form:** Submit the link to your GitHub repository using the following form: [https://forms.gle/kP24R5rkhyPLxnmR8](https://forms.gle/kP24R5rkhyPLxnmR8)

**Goal:** The final project should resemble a practical reconnaissance and vulnerability assessment tool that demonstrates real-world cybersecurity automation concepts. Good luck\!

