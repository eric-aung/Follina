# Follina
FollinaCTF Walkthrough

Overview: 
This report documents my analysis of a malicious Word document exploiting the Follina vulnerability (CVE-2022-30190), completed as part of a Blue Team Labs challenge. The investigation covers file identification, static analysis, dynamic behaviour, detection engineering, and MITRE ATT&CK mapping.

Tools Used

VirusTotal - hash lookup, file type identification, contacted URLs
Linux CLI - sha1sum, cat, file extraction
Any.run / online sandbox — behavioural analysis, MITRE mapping
OSINT / Huntress blog — detection rule research

Q 1: What is the SHA1 hash value of the sample?

There are two ways to obtain SHA1 hash of sample document file, either by running sha1sum command on Kali Linux or via Details tab in VirusTotal

![SHA1 Hash Evidence](https://github.com/eric-aung/Follina/blob/ce822f1c7e864aa480bcf061369436b65151d322/SHA1%20hash%20value.jpg?raw=true)

![Linux SHA 1 Sum](https://github.com/eric-aung/Follina/blob/935ade7dbf6eb41b0f51cf3dcdd0919f6e8ee6fb/File%20Type.jpg?raw=true)

Q 2: According to VirusTotal, what is the full filetype of the provided sample? (Format: X X X X)

Despite being named sample.doc, VirusTotal's Details tab identified the true file type as an Office Open XML Document. This matters because .docx files are ZIP archives containing XML files; one of which stores the malicious external reference used in this exploit.

![File Type](https://github.com/eric-aung/Follina/blob/935ade7dbf6eb41b0f51cf3dcdd0919f6e8ee6fb/File%20Type.jpg?raw=true)

Q 3:  Extract the URL that is used within the sample and submit it (Format: https://x.domain.tld/path/to/something)
Question 4) What is the name of the XML file that is storing the extracted URL? (Format: file.name.ext)

There are also two ways to extract the Url and name of XML file , same as question 1. First, malicious sample.doc was unzipped and the relationships file was read using cat word/_rels/document.xml.rels. Inside that file, the relationship entry which could be the potential answer was found. 

The domain xmlformats.com deliberately mimics the legitimate openxmlformats.org to appear trustworthy. The ! at the end of the URL is part of the Follina exploit mechanism, instructing MSDT to treat the response as a diagnostic package. VirusTotal's Relations tab also confirms this URL was contacted upon execution.

Malicious URL was found inside word/_rels/document.xml.rels. In the Office Open XML format, .rels files define relationships between document parts and external resources. This is the standard location to look for malicious external references in .docx files during static analysis.

![Image](https://github.com/eric-aung/Follina/blob/76ba9faa75afd0c2fe0a3fcd58a478f94cec3a99/Extracted%20URL.jpg?raw=true)
![Image](https://github.com/eric-aung/Follina/blob/76ba9faa75afd0c2fe0a3fcd58a478f94cec3a99/Extracted%20URL%20linux.jpg?raw=true)
![Image](https://github.com/eric-aung/Follina/blob/460dc88cd7862778a5e4cfbefa50c3f9ddc73733/q4.jpg?raw=true)
As for Q 5, security researcher John Hammond wrote that the HTML file fetched from the remote URL must be at least 4096 bytes in size to trigger Follina vulnerability. Files smaller than this threshold will not invoke the payload.

![Image](https://github.com/eric-aung/Follina/blob/22e70f3dea89ceab6496264f9d1a1a64caf39ee2/Payload%20Provoke%20bytes.jpg?raw=true)

Q 6:  After execution, the sample will try to kill a process if it is already running. What is the name of this process?

Analysis of the decoded PowerShell payload reveals the following command runs immediately after execution

![Image](https://github.com/eric-aung/Follina/blob/22e70f3dea89ceab6496264f9d1a1a64caf39ee2/Task%20Kill.jpg?raw=true)

The malware forcefully kills any running instance of msdt.exe after using it to execute the payload. This is a cleanup step; eliminating the diagnostic tool process to reduce forensic traces and avoid drawing attention.

Q 7: You were asked to write a process-based detection rule using Windows Event ID 4688. What would be the ProcessName and ParentProcessname used in this detection rule?

Windows Event ID 4688 logs new process creation events. The detection logic for Follina targets the abnormal parent-child relationship where Microsoft Word spawns the diagnostic tool.

![Image](https://github.com/eric-aung/Follina/blob/22e70f3dea89ceab6496264f9d1a1a64caf39ee2/Process%20and%20Parent%20Process.jpg?raw=true)

From above screenshot, it shows that msdt.ext appears as a direct child of WINWORD.EXE, which is impossible. Word should never launch MSDT under normal operation and this parent-child relationship is potential indicator of compromise.

As for Q 8 and 9 which is MITRE technique ID for Execution and CVE of Follina, I easily searched them up in VirusTotal.

![Image](https://github.com/eric-aung/Follina/blob/22e70f3dea89ceab6496264f9d1a1a64caf39ee2/Mitre%20Technique.jpg?raw=true)

![Image](https://github.com/eric-aung/Follina/blob/22e70f3dea89ceab6496264f9d1a1a64caf39ee2/CVE%20Follina.jpg?raw=true)







