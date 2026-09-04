# Letter of Recommendation

*[Draft prepared for a Mitacs application. Replace the bracketed placeholders — recommender name, title, institution, contact details, dates, and the exact program name — before sending. Guidance notes appear in italics and should be deleted from the final version. If your referee will submit through the Mitacs online portal, this text can be pasted into the reference form or attached as a signed letter on institutional letterhead.]*

---

[Recommender Full Name]
[Title / Position, e.g. Associate Professor of Computer Science]
[Department], [University / Institution]
[Address]
[Email] · [Phone]

[Date]

**To the Mitacs Selection Committee,**

**Re: Recommendation of Marwen Ben Ahmed for the [Mitacs Globalink Research Internship / Accelerate / program name]**

I am writing to offer my strong recommendation for Marwen Ben Ahmed, a computer science engineering student whom I have known for [duration, e.g. two years] in my capacity as [relationship, e.g. his instructor in Systems Security and supervisor for his year-end project]. Over that time Marwen has distinguished himself as one of the more capable, self-directed, and intellectually curious students I have taught, and I believe he would be an excellent fit for a Mitacs research internship.

My assessment is grounded in a substantial independent project Marwen designed and built between December 2025 and early 2026: an **Entra ID and hybrid adversary-emulation laboratory** focused on Adversary-in-the-Middle (AiTM) phishing against Microsoft 365 and Microsoft Entra ID. What impressed me was not any single component but the breadth of competence the project required and the maturity with which Marwen executed it end to end, on his own initiative.

**Technical depth and range.** The project spans several domains that are rarely combined by a student at this stage:

- **Infrastructure-as-Code.** Marwen provisioned the entire lab reproducibly using Terraform on AWS — automating EC2 provisioning in the `eu-west-3` region, generating 4096-bit RSA key pairs, configuring security groups, IAM roles and instance profiles (including SSM access), and wiring Elastic IP association and output-driven inventory generation. The code is clean, parameterized through variables, and clearly documented.
- **Configuration management.** He layered Ansible playbooks on top of Terraform to configure the red-team host automatically — installing the toolchain, building software from source, and managing the phishing proxy setup — with an auto-generated inventory bridging the two tools.
- **Cloud identity security.** The emulation itself demonstrates a sophisticated understanding of modern identity attacks: real-time session relay to bypass multi-factor authentication, theft of session cookies and OAuth access/refresh tokens, post-exploitation against the Microsoft Graph API, and the risks specific to hybrid environments synced through Entra Connect.
- **Rigor and framing.** Marwen mapped his work to the MITRE ATT&CK cloud matrix (T1566.002, T1555, T1078.004, T1528) and, throughout, emphasized the corresponding detection and prevention controls — phishing-resistant MFA, conditional access, and monitoring for token replay and impossible travel.

**Independence and follow-through.** The project's commit history tells the story of a student who works iteratively and does not abandon problems: he stood up the infrastructure, debugged SSH and provisioning issues until "everything works properly," migrated his environment when his first approach proved awkward, and later returned to reorganize and clean up the repository. This is the disposition of someone who can be handed an open-ended research problem and trusted to make steady progress with limited supervision — exactly what a Mitacs internship demands.

**Professional judgment and ethics.** I want to underline this point, because it matters in security research. Marwen framed the entire project as an authorized, isolated educational exercise. His documentation states plainly that no real users or production systems were targeted, foregrounds the defensive lessons, and deliberately withholds operational offensive material. He treats security knowledge as something to be used responsibly, which reflects the professional maturity Mitacs and its partner organizations should expect.

**Communication.** Finally, Marwen documents his work unusually well. The repository's write-ups explain architecture, setup, and findings clearly enough that a newcomer could follow them — a skill that translates directly to the reports, presentations, and collaboration a research internship involves.

In summary, Marwen combines strong technical ability across cloud infrastructure, automation, and security with initiative, sound judgment, and clear communication. I recommend him without reservation and would be glad to expand on any of the above. Please feel free to contact me at [email] or [phone].

Sincerely,

[Recommender Full Name]
[Title]
[Department], [Institution]
