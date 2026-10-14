# MITRE ATT&CK Enterprise v19.2 Dataset Inspection
**Source File:** `data/enterprise-attack-v19.2.xlsx`  **Format:** Microsoft Excel Spreadsheet (.xlsx)  **Framework Version:** MITRE ATT&CK Enterprise Matrix v19.2 (Official Release)  **Sheet Count:** 13

---

## 1. Sheet Overview

| # | Sheet Name | Row Count | Column Count | Description / Role |
|---|---|---|---|---|
| 1 | `techniques` | 697 | 17 | Techniques and sub-techniques catalog with tactics, platforms, and IDs |
| 2 | `tactics` | 15 | 9 | Official MITRE enterprise tactics (kill-chain stages) |
| 3 | `software` | 825 | 14 | Malware and adversary utility software tools |
| 4 | `groups` | 176 | 13 | Threat actor groups / intrusion-sets with names and aliases |
| 5 | `campaigns` | 56 | 17 | Adversary campaigns with historical operational windows |
| 6 | `mitigations` | 44 | 10 | Preventative security measures and hardening controls |
| 7 | `Enterprise ATT&CK matrix` | 132 | 30 | 2D tabular layout of techniques arranged across tactics |
| 8 | `relationships` | 20,628 | 13 | Core relational graph (group uses technique, malware uses technique, etc.) |
| 9 | `datacomponents` | 106 | 9 | Telemetry components and event collection anchors |
| 10 | `analytics` | 1,758 | 9 | Detection analytic definitions and logic |
| 11 | `detectionstrategies` | 697 | 9 | Strategic detection coverage abstractions |
| 12 | `defensive mappings` | 4,160 | 11 | Cross-mappings between detections and data components |
| 13 | `citations` | 4,305 | 3 | Bibliographic literature references for intelligence claims |

---

## 2. Detailed Sheet Schemas & First 2 Sample Rows

### 2.1 Sheet: `techniques`

- **Total Rows:** 697
- **Total Columns:** 17
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`, `tactics`, `platforms`, `is sub-technique`, `sub-technique of`, `contributors`, `supports remote`, `impact type`, `relationship citations`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 697 | `str` | 0.0% |
| `STIX ID` | 697 | `str` | 0.0% |
| `name` | 697 | `str` | 0.0% |
| `description` | 697 | `str` | 0.0% |
| `url` | 697 | `str` | 0.0% |
| `created` | 697 | `str` | 0.0% |
| `last modified` | 697 | `str` | 0.0% |
| `domain` | 697 | `str` | 0.0% |
| `version` | 697 | `float64` | 0.0% |
| `tactics` | 697 | `str` | 0.0% |
| `platforms` | 697 | `str` | 0.0% |
| `is sub-technique` | 697 | `bool` | 0.0% |
| `sub-technique of` | 475 | `str` | 31.9% |
| `contributors` | 437 | `str` | 37.3% |
| `supports remote` | 52 | `float64` | 92.5% |
| `impact type` | 33 | `str` | 95.3% |
| `relationship citations` | 697 | `str` | 0.0% |

#### Sample Records (First 2 Rows):

| ID        | STIX ID                                              | name                                                           | description                                                                    | url                                           | created         | last modified   | domain            |   version | tactics              | platforms                                                    | is sub-technique   | sub-technique of   | contributors                | supports remote   | impact type   | relationship citations                                                         |
|:----------|:-----------------------------------------------------|:---------------------------------------------------------------|:-------------------------------------------------------------------------------|:----------------------------------------------|:----------------|:----------------|:------------------|----------:|:---------------------|:-------------------------------------------------------------|:-------------------|:-------------------|:----------------------------|:------------------|:--------------|:-------------------------------------------------------------------------------|
| T1548     | attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b | Abuse Elevation Control Mechanism                              | Adversaries may circumvent mechanisms designed to control privilege elevati... | https://attack.mitre.org/techniques/T1548     | 30 January 2020 | 12 May 2026     | enterprise-attack |         2 | Privilege Escalation | IaaS, Identity Provider, Linux, Office Suite, Windows, macOS | False              |                    |                             |                   |               | (Citation: TrendMicro RaspberryRobin 2022),(Citation: Google Cloud Threat I... |
| T1548.002 | attack-pattern--120d5519-3098-4e1c-9191-2aa61232f073 | Abuse Elevation Control Mechanism: Bypass User Account Control | Adversaries may bypass UAC mechanisms to elevate process privileges on syst... | https://attack.mitre.org/techniques/T1548/002 | 30 January 2020 | 12 May 2026     | enterprise-attack |         3 | Privilege Escalation | Windows                                                      | True               | T1548              | Casey Smith; Stefan Kanthak |                   |               | (Citation: ESET Grandoreiro April 2020),(Citation: Arxiv Avaddon Feb 2021),... |

---

### 2.2 Sheet: `tactics`

- **Total Rows:** 15
- **Total Columns:** 9
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 15 | `str` | 0.0% |
| `STIX ID` | 15 | `str` | 0.0% |
| `name` | 15 | `str` | 0.0% |
| `description` | 15 | `str` | 0.0% |
| `url` | 15 | `str` | 0.0% |
| `created` | 15 | `str` | 0.0% |
| `last modified` | 15 | `str` | 0.0% |
| `domain` | 15 | `str` | 0.0% |
| `version` | 15 | `float64` | 0.0% |

#### Sample Records (First 2 Rows):

| ID     | STIX ID                                              | name                | description                                                                    | url                                     | created         | last modified     | domain            |   version |
|:-------|:-----------------------------------------------------|:--------------------|:-------------------------------------------------------------------------------|:----------------------------------------|:----------------|:------------------|:------------------|----------:|
| TA0009 | x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe | Collection          | The adversary is trying to gather data of interest to their goal.              | https://attack.mitre.org/tactics/TA0009 | 17 October 2018 | 05 September 2024 | enterprise-attack |       1.1 |
|        |                                                      |                     |                                                                                |                                         |                 |                   |                   |           |
|        |                                                      |                     | Collecti...                                                                    |                                         |                 |                   |                   |           |
| TA0011 | x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813 | Command and Control | The adversary is trying to communicate with compromised systems to control ... | https://attack.mitre.org/tactics/TA0011 | 17 October 2018 | 25 April 2025     | enterprise-attack |       1   |

---

### 2.3 Sheet: `software`

- **Total Rows:** 825
- **Total Columns:** 14
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`, `contributors`, `platforms`, `aliases`, `type`, `relationship citations`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 825 | `str` | 0.0% |
| `STIX ID` | 825 | `str` | 0.0% |
| `name` | 825 | `str` | 0.0% |
| `description` | 825 | `str` | 0.0% |
| `url` | 825 | `str` | 0.0% |
| `created` | 825 | `str` | 0.0% |
| `last modified` | 825 | `str` | 0.0% |
| `domain` | 825 | `str` | 0.0% |
| `version` | 825 | `float64` | 0.0% |
| `contributors` | 196 | `str` | 76.2% |
| `platforms` | 788 | `str` | 4.5% |
| `aliases` | 166 | `str` | 79.9% |
| `type` | 825 | `str` | 0.0% |
| `relationship citations` | 825 | `str` | 0.0% |

#### Sample Records (First 2 Rows):

| ID    | STIX ID                                       | name      | description                                                                    | url                                     | created     | last modified   | domain            |   version | contributors   | platforms   | aliases   | type    | relationship citations                                                     |
|:------|:----------------------------------------------|:----------|:-------------------------------------------------------------------------------|:----------------------------------------|:------------|:----------------|:------------------|----------:|:---------------|:------------|:----------|:--------|:---------------------------------------------------------------------------|
| S0066 | malware--7bec698a-7e20-4fd3-bb6a-12787770fb1a | 3PARA RAT | [3PARA RAT](https://attack.mitre.org/software/S0066) is a remote access too... | https://attack.mitre.org/software/S0066 | 31 May 2017 | 25 April 2025   | enterprise-attack |       1.1 |                | Windows     |           | malware | (Citation: CrowdStrike Putter Panda),,(Citation: CrowdStrike Putter Panda) |
| S0065 | malware--8e461ca3-0996-4e6e-a0df-e2a5bbc51ebc | 4H RAT    | [4H RAT](https://attack.mitre.org/software/S0065) is malware that has been ... | https://attack.mitre.org/software/S0065 | 31 May 2017 | 25 April 2025   | enterprise-attack |       1.1 |                | Windows     |           | malware | (Citation: CrowdStrike Putter Panda),,(Citation: CrowdStrike Putter Panda) |

---

### 2.4 Sheet: `groups`

- **Total Rows:** 176
- **Total Columns:** 13
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`, `contributors`, `associated groups`, `associated groups citations`, `relationship citations`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 176 | `str` | 0.0% |
| `STIX ID` | 176 | `str` | 0.0% |
| `name` | 176 | `str` | 0.0% |
| `description` | 176 | `str` | 0.0% |
| `url` | 176 | `str` | 0.0% |
| `created` | 176 | `str` | 0.0% |
| `last modified` | 176 | `str` | 0.0% |
| `domain` | 176 | `str` | 0.0% |
| `version` | 176 | `float64` | 0.0% |
| `contributors` | 100 | `str` | 43.2% |
| `associated groups` | 107 | `str` | 39.2% |
| `associated groups citations` | 106 | `str` | 39.8% |
| `relationship citations` | 176 | `str` | 0.0% |

#### Sample Records (First 2 Rows):

| ID    | STIX ID                                             | name     | description                                                                    | url                                   | created       | last modified   | domain                          |   version | contributors               | associated groups                                                              | associated groups citations                                                    | relationship citations                                                         |
|:------|:----------------------------------------------------|:---------|:-------------------------------------------------------------------------------|:--------------------------------------|:--------------|:----------------|:--------------------------------|----------:|:---------------------------|:-------------------------------------------------------------------------------|:-------------------------------------------------------------------------------|:-------------------------------------------------------------------------------|
| G1028 | intrusion-set--8332952e-b86b-486b-acc3-1c2a85d39394 | APT-C-23 | [APT-C-23](https://attack.mitre.org/groups/G1028) is a threat group that ha... | https://attack.mitre.org/groups/G1028 | 26 March 2024 | 31 July 2026    | enterprise-attack,mobile-attack |         1 | Sittikorn Sangrattanapitak | Arid Viper, Big Bang APT, Desert Falcon, Grey Karkadann, Mantis, TAG-63, Tw... | (Citation: welivesecurity_apt-c-23)(Citation: sentinelone_israel_hamas_war)... | ,,                                                                             |
| G0099 | intrusion-set--c4d50cdf-87ce-407d-86d8-862883485842 | APT-C-36 | [APT-C-36](https://attack.mitre.org/groups/G0099) is a suspected South Amer... | https://attack.mitre.org/groups/G0099 | 05 May 2020   | 31 July 2026    | enterprise-attack               |         2 | Jose Luis Sánchez Martinez | APT-Q-98, AguilaCiega, Blind Eagle, TAG-144                                    | (Citation: Recorded Future TAG-144 AUG 2025), (Citation: Recorded Future TA... | (Citation: Zscaler BlindEagle DEC 2025),(Citation: QiAnXin APT-C-36 Feb2019... |

---

### 2.5 Sheet: `campaigns`

- **Total Rows:** 56
- **Total Columns:** 17
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`, `associated campaigns`, `associated campaigns citations`, `first seen`, `first seen citation`, `last seen`, `last seen citation`, `contributors`, `relationship citations`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 56 | `str` | 0.0% |
| `STIX ID` | 56 | `str` | 0.0% |
| `name` | 56 | `str` | 0.0% |
| `description` | 56 | `str` | 0.0% |
| `url` | 56 | `str` | 0.0% |
| `created` | 56 | `str` | 0.0% |
| `last modified` | 56 | `str` | 0.0% |
| `domain` | 56 | `str` | 0.0% |
| `version` | 56 | `float64` | 0.0% |
| `associated campaigns` | 3 | `str` | 94.6% |
| `associated campaigns citations` | 1 | `str` | 98.2% |
| `first seen` | 56 | `str` | 0.0% |
| `first seen citation` | 56 | `str` | 0.0% |
| `last seen` | 56 | `str` | 0.0% |
| `last seen citation` | 56 | `str` | 0.0% |
| `contributors` | 16 | `str` | 71.4% |
| `relationship citations` | 56 | `str` | 0.0% |

#### Sample Records (First 2 Rows):

| ID    | STIX ID                                        | name                               | description                                                                    | url                                      | created           | last modified   | domain                       |   version | associated campaigns   | associated campaigns citations   | first seen       | first seen citation                                               | last seen        | last seen citation                                                | contributors   | relationship citations                                                         |
|:------|:-----------------------------------------------|:-----------------------------------|:-------------------------------------------------------------------------------|:-----------------------------------------|:------------------|:----------------|:-----------------------------|----------:|:-----------------------|:---------------------------------|:-----------------|:------------------------------------------------------------------|:-----------------|:------------------------------------------------------------------|:---------------|:-------------------------------------------------------------------------------|
| C0028 | campaign--46421788-b6e1-4256-b351-f8beffd1afba | 2015 Ukraine Electric Power Attack | [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C00... | https://attack.mitre.org/campaigns/C0028 | 27 September 2023 | 04 August 2026  | enterprise-attack,ics-attack |         1 |                        |                                  | 01 December 2015 | (Citation: Booz Allen Hamilton)                                   | 01 January 2016  | (Citation: Booz Allen Hamilton)                                   |                | (Citation: Booz Allen Hamilton),(Citation: Booz Allen Hamilton),(Citation: ... |
| C0025 | campaign--aa73efef-1418-4dbe-b43c-87a498e97234 | 2016 Ukraine Electric Power Attack | [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C00... | https://attack.mitre.org/campaigns/C0025 | 31 March 2023     | 31 July 2026    | enterprise-attack,ics-attack |         1 |                        |                                  | 01 December 2016 | (Citation: ESET Industroyer)(Citation: Dragos Crashoverride 2018) | 01 December 2016 | (Citation: ESET Industroyer)(Citation: Dragos Crashoverride 2018) |                | (Citation: ESET Industroyer),(Citation: Dragos Crashoverride 2018),(Citatio... |

---

### 2.6 Sheet: `mitigations`

- **Total Rows:** 44
- **Total Columns:** 10
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`, `relationship citations`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 44 | `str` | 0.0% |
| `STIX ID` | 44 | `str` | 0.0% |
| `name` | 44 | `str` | 0.0% |
| `description` | 44 | `str` | 0.0% |
| `url` | 44 | `str` | 0.0% |
| `created` | 44 | `str` | 0.0% |
| `last modified` | 44 | `str` | 0.0% |
| `domain` | 44 | `str` | 0.0% |
| `version` | 44 | `float64` | 0.0% |
| `relationship citations` | 39 | `str` | 11.4% |

#### Sample Records (First 2 Rows):

| ID    | STIX ID                                                | name                           | description                                                                    | url                                        | created      | last modified    | domain            |   version | relationship citations                                                         |
|:------|:-------------------------------------------------------|:-------------------------------|:-------------------------------------------------------------------------------|:-------------------------------------------|:-------------|:-----------------|:------------------|----------:|:-------------------------------------------------------------------------------|
| M1036 | course-of-action--f9f9e6ef-bc0a-41ad-ba11-0924e5e84c4c | Account Use Policies           | Account Use Policies help mitigate unauthorized access by configuring and e... | https://attack.mitre.org/mitigations/M1036 | 11 June 2019 | 12 May 2026      | enterprise-attack |       1.1 | (Citation: AWS Data Perimeters),(Citation: Microsoft Developer Support Powe... |
| M1015 | course-of-action--e3388c78-2a8d-47c2-8422-c1398b324462 | Active Directory Configuration | Implement robust Active Directory (AD) configurations using group policies ... | https://attack.mitre.org/mitigations/M1015 | 06 June 2019 | 10 December 2024 | enterprise-attack |       1.2 | (Citation: SpecterOps Certified Pre Owned),(Citation: Microsoft Trust Consi... |

---

### 2.7 Sheet: `Enterprise ATT&CK matrix`

- **Total Rows:** 132
- **Total Columns:** 30
- **Column List:** `Reconnaissance`, `Unnamed: 1`, `Resource Development`, `Unnamed: 3`, `Initial Access`, `Unnamed: 5`, `Execution`, `Unnamed: 7`, `Persistence`, `Unnamed: 9`, `Privilege Escalation`, `Unnamed: 11`, `Stealth`, `Unnamed: 13`, `Defense Impairment`, `Unnamed: 15`, `Credential Access`, `Unnamed: 17`, `Discovery`, `Unnamed: 19`, `Lateral Movement`, `Unnamed: 21`, `Collection`, `Unnamed: 23`, `Command and Control`, `Unnamed: 25`, `Exfiltration`, `Unnamed: 27`, `Impact`, `Unnamed: 29`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `Reconnaissance` | 12 | `str` | 90.9% |
| `Unnamed: 1` | 34 | `str` | 74.2% |
| `Resource Development` | 9 | `str` | 93.2% |
| `Unnamed: 3` | 41 | `str` | 68.9% |
| `Initial Access` | 11 | `str` | 91.7% |
| `Unnamed: 5` | 11 | `str` | 91.7% |
| `Execution` | 20 | `str` | 84.8% |
| `Unnamed: 7` | 44 | `str` | 66.7% |
| `Persistence` | 22 | `str` | 83.3% |
| `Unnamed: 9` | 91 | `str` | 31.1% |
| `Privilege Escalation` | 13 | `str` | 90.2% |
| `Unnamed: 11` | 83 | `str` | 37.1% |
| `Stealth` | 30 | `str` | 77.3% |
| `Unnamed: 13` | 118 | `str` | 10.6% |
| `Defense Impairment` | 18 | `str` | 86.4% |
| `Unnamed: 15` | 38 | `str` | 71.2% |
| `Credential Access` | 17 | `str` | 87.1% |
| `Unnamed: 17` | 50 | `str` | 62.1% |
| `Discovery` | 34 | `str` | 74.2% |
| `Unnamed: 19` | 15 | `str` | 88.6% |
| `Lateral Movement` | 9 | `str` | 93.2% |
| `Unnamed: 21` | 14 | `str` | 89.4% |
| `Collection` | 17 | `str` | 87.1% |
| `Unnamed: 23` | 24 | `str` | 81.8% |
| `Command and Control` | 18 | `str` | 86.4% |
| `Unnamed: 25` | 27 | `str` | 79.5% |
| `Exfiltration` | 9 | `str` | 93.2% |
| `Unnamed: 27` | 10 | `str` | 92.4% |
| `Impact` | 15 | `str` | 88.6% |
| `Unnamed: 29` | 18 | `str` | 86.4% |

#### Sample Records (First 2 Rows):

| Reconnaissance   | Unnamed: 1             | Resource Development   | Unnamed: 3   | Initial Access      | Unnamed: 5   | Execution                    | Unnamed: 7   | Persistence          | Unnamed: 9                   | Privilege Escalation              | Unnamed: 11                    | Stealth                   | Unnamed: 13                | Defense Impairment                | Unnamed: 15             | Credential Access       | Unnamed: 17         | Discovery         | Unnamed: 19    | Lateral Movement                | Unnamed: 21   | Collection              | Unnamed: 23         | Command and Control        | Unnamed: 25             | Exfiltration              | Unnamed: 27         | Impact                 | Unnamed: 29                  |
|:-----------------|:-----------------------|:-----------------------|:-------------|:--------------------|:-------------|:-----------------------------|:-------------|:---------------------|:-----------------------------|:----------------------------------|:-------------------------------|:--------------------------|:---------------------------|:----------------------------------|:------------------------|:------------------------|:--------------------|:------------------|:---------------|:--------------------------------|:--------------|:------------------------|:--------------------|:---------------------------|:------------------------|:--------------------------|:--------------------|:-----------------------|:-----------------------------|
| Active Scanning  | Scanning IP Blocks     | Acquire Access         |              | Content Injection   |              | BITS Jobs                    |              | Account Manipulation | Additional Cloud Credentials | Abuse Elevation Control Mechanism | Bypass User Account Control    | Access Token Manipulation | Create Process with Token  | Disable or Modify System Firewall | Cloud Firewall          | Adversary-in-the-Middle | ARP Cache Poisoning | Account Discovery | Cloud Account  | Exploitation of Remote Services |               | Adversary-in-the-Middle | ARP Cache Poisoning | Application Layer Protocol | DNS                     | Automated Exfiltration    | Traffic Duplication | Account Access Removal |                              |
|                  | Vulnerability Scanning | Acquire Infrastructure | Botnet       | Drive-by Compromise |              | Cloud Administration Command |              |                      | Additional Cloud Roles       |                                   | Elevated Execution with Prompt |                           | Make and Impersonate Token |                                   | Network Device Firewall |                         | DHCP Spoofing       |                   | Domain Account | Internal Spearphishing          |               |                         | DHCP Spoofing       |                            | File Transfer Protocols | Data Transfer Size Limits |                     | Data Destruction       | Lifecycle-Triggered Deletion |

---

### 2.8 Sheet: `relationships`

- **Total Rows:** 20,628
- **Total Columns:** 13
- **Column List:** `source ID`, `source name`, `source ref`, `source type`, `mapping type`, `target ID`, `target name`, `target ref`, `target type`, `mapping description`, `STIX ID`, `created`, `last modified`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `source ID` | 20,628 | `str` | 0.0% |
| `source name` | 20,628 | `str` | 0.0% |
| `source ref` | 20,628 | `str` | 0.0% |
| `source type` | 20,628 | `str` | 0.0% |
| `mapping type` | 20,628 | `str` | 0.0% |
| `target ID` | 20,628 | `str` | 0.0% |
| `target name` | 20,628 | `str` | 0.0% |
| `target ref` | 20,628 | `str` | 0.0% |
| `target type` | 20,628 | `str` | 0.0% |
| `mapping description` | 19,925 | `str` | 3.4% |
| `STIX ID` | 20,628 | `str` | 0.0% |
| `created` | 20,628 | `str` | 0.0% |
| `last modified` | 20,628 | `str` | 0.0% |

#### Sample Records (First 2 Rows):

| source ID   | source name                        | source ref                                     | source type   | mapping type   | target ID   | target name   | target ref                                          | target type   | mapping description                                                            | STIX ID                                            | created           | last modified   |
|:------------|:-----------------------------------|:-----------------------------------------------|:--------------|:---------------|:------------|:--------------|:----------------------------------------------------|:--------------|:-------------------------------------------------------------------------------|:---------------------------------------------------|:------------------|:----------------|
| C0028       | 2015 Ukraine Electric Power Attack | campaign--46421788-b6e1-4256-b351-f8beffd1afba | campaign      | attributed-to  | G0034       | Sandworm Team | intrusion-set--381fcf73-60f6-4ab2-9991-6af3cbc35192 | group         | (Citation: Andy Greenberg June 2017) (Citation: US District Court Indictmen... | relationship--4d407dda-944a-4974-b1c2-0a04d2c9ee4c | 27 September 2023 | 04 August 2026  |
| C0025       | 2016 Ukraine Electric Power Attack | campaign--aa73efef-1418-4dbe-b43c-87a498e97234 | campaign      | attributed-to  | G0034       | Sandworm Team | intrusion-set--381fcf73-60f6-4ab2-9991-6af3cbc35192 | group         | (Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citati... | relationship--90647f03-38a4-4364-a3af-53640a81360e | 31 March 2023     | 31 July 2026    |

---

### 2.9 Sheet: `datacomponents`

- **Total Rows:** 106
- **Total Columns:** 9
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 106 | `str` | 0.0% |
| `STIX ID` | 106 | `str` | 0.0% |
| `name` | 106 | `str` | 0.0% |
| `description` | 106 | `str` | 0.0% |
| `url` | 106 | `str` | 0.0% |
| `created` | 106 | `str` | 0.0% |
| `last modified` | 106 | `str` | 0.0% |
| `domain` | 106 | `str` | 0.0% |
| `version` | 106 | `float64` | 0.0% |

#### Sample Records (First 2 Rows):

| ID     | STIX ID                                                      | name                                | description                                                                    | url                                            | created         | last modified    | domain            |   version |
|:-------|:-------------------------------------------------------------|:------------------------------------|:-------------------------------------------------------------------------------|:-----------------------------------------------|:----------------|:-----------------|:------------------|----------:|
| DC0103 | x-mitre-data-component--2e521444-7295-4dec-96c1-7595b2df7811 | Active DNS                          | "Domain Name: Active DNS" data component captures queried DNS registry data... | https://attack.mitre.org/datacomponents/DC0103 | 20 October 2021 | 21 October 2025  | enterprise-attack |         2 |
| DC0084 | x-mitre-data-component--02d090b6-8157-48da-98a2-517f7edd49fc | Active Directory Credential Request | Requests for authentication credentials via Kerberos or other methods like ... | https://attack.mitre.org/datacomponents/DC0084 | 20 October 2021 | 12 November 2025 | enterprise-attack |         2 |

---

### 2.10 Sheet: `analytics`

- **Total Rows:** 1,758
- **Total Columns:** 9
- **Column List:** `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 1,758 | `str` | 0.0% |
| `STIX ID` | 1,758 | `str` | 0.0% |
| `name` | 1,758 | `str` | 0.0% |
| `description` | 1,758 | `str` | 0.0% |
| `url` | 1,758 | `str` | 0.0% |
| `created` | 1,758 | `str` | 0.0% |
| `last modified` | 1,758 | `str` | 0.0% |
| `domain` | 1,758 | `str` | 0.0% |
| `version` | 1,758 | `float64` | 0.0% |

#### Sample Records (First 2 Rows):

| ID     | STIX ID                                                | name          | description                                                                    | url                                                         | created         | last modified    | domain            |   version |
|:-------|:-------------------------------------------------------|:--------------|:-------------------------------------------------------------------------------|:------------------------------------------------------------|:----------------|:-----------------|:------------------|----------:|
| AN0001 | x-mitre-analytic--f4af0b1b-db51-4266-8b02-2cdfcb191f60 | Analytic 0001 | Detects access attempts to cloud instance metadata endpoints (e.g., 169.254... | https://attack.mitre.org/detectionstrategies/DET0001#AN0001 | 21 October 2025 | 12 November 2025 | enterprise-attack |         1 |
| AN0002 | x-mitre-analytic--ee4e3e61-e138-498b-93bf-3a5f8fea691c | Analytic 0002 | Detects non-standard processes (e.g., PowerShell, python.exe, rundll32.exe)... | https://attack.mitre.org/detectionstrategies/DET0002#AN0002 | 21 October 2025 | 12 November 2025 | enterprise-attack |         1 |

---

### 2.11 Sheet: `detectionstrategies`

- **Total Rows:** 697
- **Total Columns:** 9
- **Column List:** `ID`, `STIX ID`, `name`, `url`, `created`, `last modified`, `domain`, `version`, `analytic_refs`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `ID` | 697 | `str` | 0.0% |
| `STIX ID` | 697 | `str` | 0.0% |
| `name` | 697 | `str` | 0.0% |
| `url` | 697 | `str` | 0.0% |
| `created` | 697 | `str` | 0.0% |
| `last modified` | 697 | `str` | 0.0% |
| `domain` | 697 | `str` | 0.0% |
| `version` | 697 | `float64` | 0.0% |
| `analytic_refs` | 697 | `str` | 0.0% |

#### Sample Records (First 2 Rows):

| ID      | STIX ID                                                          | name                                                  | url                                                  | created         | last modified   | domain            |   version | analytic_refs                                                                  |
|:--------|:-----------------------------------------------------------------|:------------------------------------------------------|:-----------------------------------------------------|:----------------|:----------------|:------------------|----------:|:-------------------------------------------------------------------------------|
| DET0210 | x-mitre-detection-strategy--ba7a75c6-fcf5-4f36-8908-1fe1c30f690f | Abuse of Domain Accounts                              | https://attack.mitre.org/detectionstrategies/DET0210 | 21 October 2025 | 12 May 2026     | enterprise-attack |         1 | x-mitre-analytic--c7706ddb-cf88-41c7-981b-a5e1bf6cfcfc; x-mitre-analytic--7... |
| DET0413 | x-mitre-detection-strategy--48e8d8b1-0117-48bd-a32d-f4e43b665bf3 | Abuse of Information Repositories for Data Collection | https://attack.mitre.org/detectionstrategies/DET0413 | 21 October 2025 | 12 May 2026     | enterprise-attack |         1 | x-mitre-analytic--7dce56f3-43db-4787-ae13-bd2ce6851088; x-mitre-analytic--5... |

---

### 2.12 Sheet: `defensive mappings`

- **Total Rows:** 4,160
- **Total Columns:** 11
- **Column List:** `detection_strategy_attack_id`, `detection_strategy_id`, `detection_strategy_name`, `analytic_id`, `analytic_name`, `platforms`, `log_source_name`, `channel`, `data_component_id`, `data_component_name`, `data_component_attack_id`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `detection_strategy_attack_id` | 4,160 | `str` | 0.0% |
| `detection_strategy_id` | 4,160 | `str` | 0.0% |
| `detection_strategy_name` | 4,160 | `str` | 0.0% |
| `analytic_id` | 4,160 | `str` | 0.0% |
| `analytic_name` | 4,160 | `str` | 0.0% |
| `platforms` | 4,160 | `str` | 0.0% |
| `log_source_name` | 4,160 | `str` | 0.0% |
| `channel` | 4,033 | `str` | 3.1% |
| `data_component_id` | 4,160 | `str` | 0.0% |
| `data_component_name` | 4,160 | `str` | 0.0% |
| `data_component_attack_id` | 4,160 | `str` | 0.0% |

#### Sample Records (First 2 Rows):

| detection_strategy_attack_id   | detection_strategy_id                                            | detection_strategy_name                                                        | analytic_id                                            | analytic_name   | platforms   | log_source_name      | channel              | data_component_id                                            | data_component_name    | data_component_attack_id   |
|:-------------------------------|:-----------------------------------------------------------------|:-------------------------------------------------------------------------------|:-------------------------------------------------------|:----------------|:------------|:---------------------|:---------------------|:-------------------------------------------------------------|:-----------------------|:---------------------------|
| DET0103                        | x-mitre-detection-strategy--00060b87-7f99-45aa-9553-a4d94139195c | Behavioral Detection of Network Share Connection Removal via CLI and SMB Di... | x-mitre-analytic--5d47e6b2-04fb-45ab-be98-7de1baabf508 | AN0286          | Windows     | WinEventLog:Security | EventCode=4624, 4648 | x-mitre-data-component--9ce98c86-8d30-4043-ba54-0784d478d0b5 | Logon Session Creation | DC0067                     |
| DET0103                        | x-mitre-detection-strategy--00060b87-7f99-45aa-9553-a4d94139195c | Behavioral Detection of Network Share Connection Removal via CLI and SMB Di... | x-mitre-analytic--5d47e6b2-04fb-45ab-be98-7de1baabf508 | AN0286          | Windows     | WinEventLog:Sysmon   | EventCode=1          | x-mitre-data-component--3d20385b-24ef-40e1-9f56-f39750379077 | Process Creation       | DC0032                     |

---

### 2.13 Sheet: `citations`

- **Total Rows:** 4,305
- **Total Columns:** 3
- **Column List:** `reference`, `citation`, `url`

#### Column Data Types & Completeness:

| Column Name | Non-Null Count | Data Type | Null Percentage |
|---|---|---|---|
| `reference` | 4,305 | `str` | 0.0% |
| `citation` | 4,305 | `str` | 0.0% |
| `url` | 4,272 | `str` | 0.8% |

#### Sample Records (First 2 Rows):

| reference      | citation                                                                       | url                                                           |
|:---------------|:-------------------------------------------------------------------------------|:--------------------------------------------------------------|
| 00sec Droppers | 0x00pico. (2017, September 25). Super-Stealthy Droppers. Retrieved October ... | https://0x00sec.org/t/super-stealthy-droppers/3715            |
| 1 - appv       | SEONGSU PARK. (2022, December 27). BlueNoroff introduces new methods bypass... | https://securelist.com/bluenoroff-methods-bypass-motw/108383/ |

---

## 3. Relationship Deep Dive (`relationships` Sheet)

- **Total Relationships in Sheet:** 20,628
- **Mapping Type Distribution:**
  - `uses`: 18,457
  - `mitigates`: 1,448
  - `detects`: 697
  - `attributed-to`: 26
- **Source Entity Distribution:**
  - `software`: 11,362
  - `group`: 5,777
  - `mitigation`: 1,448
  - `campaign`: 1,344
  - `detectionstrategy`: 697
- **Target Entity Distribution:**
  - `technique`: 19,281
  - `software`: 1,321
  - `group`: 26

- **Group 'uses' Technique Relationships:** 4,628 rows
- **Unique Threat Groups referenced:** 172
- **Unique Techniques referenced (exact ID with sub-techniques):** 498
- **Unique Parent Techniques referenced (after rollup):** 203

## 4. Comparison: STIX JSON vs. XLSX v19.2 Source Verification

| Dimension | Old STIX JSON (`data/transactions.json`) | Refactored XLSX (`data/enterprise-attack-v19.2.xlsx`) | Notes |
|---|---|---|---|
| **Active Groups (Basket Size >= 2)** | 167 | 172 | ATT&CK v19.2 contains expanded group tracking |
| **Active Parent Techniques** | 222 | 203 | Standardized against v19.2 enterprise matrix |
| **Data Ingestion Method** | Remote GitHub STIX JSON (~53 MB raw download) | Local structured XLSX workbook | High-performance, offline reproducible |
| **Referential Integrity** | Unchecked in raw script | 100% verified (all source/target IDs exist in master catalogs) | Zero orphaned relationship edges |
