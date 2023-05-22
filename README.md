# Prerequisite
 [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): advanced system monitor and syslog generator 

 [ELK](https://www.elastic.co/what-is/elk-stack): data engine<br>
 
 [Python3](https://www.python.org/downloads/): drive ELK to execute all detection rules
<br>

# Usage
**1.** Import the local logs to the ELK (In my case, they are already collected within ELK) 

**2.** Change the `main.py` template we provide according to your actual needs (I've uploaded the "test_in_my_case.py" for reference as well)

**3.** Execute the `main.py` and start matching!
<br>

# Description
**1.** This rule set conforms to the query statement **DSL** of ELK engine, so we can utilize ELK to drive detections within tremendous data quickly

**2.** Open any one of the `.csv` file in `Elastic_dsl`, you will see 4 columns:
 - *Column 1: Technique id*
 - *Column 2: DSL query statement*
 - *Column 3: Attack instructions*
 - *Column 4: Remarks: (Now most of them are 2 or 2(4), don't worry)*
   - *0: Do not understand the attack command*
   - *1: The attack command requires the target to install specific software or scripts*
   - *2: Verified*
   - *2 (4): The commandline cannot be recorded by direct execution but can be seen by encapsulating the instruction with* `cmd /c "..."` *or* `powershell. exe "..."`
   - *3: To be verified*
   - *4: Commandline cannot be recorded*
   - *5: It is difficult to detect if the command is executed step by step*

**3.** The attacks for "initial access" we aquire at present are mainly implemented by phishing, which are rarely executed through the commandline, so they are not recorded yet

**4.** `multiple.csv` are a collection of techniques belonging to multiple tactics
<br>

# Future Work (defects)
**1.** Now we only include attacks against Windows systems

**2.** Now we have not developed the capability to cope with the obfuscation

**3.** Now we mainly focus on the "CommandLine" field of Sysmon logs, and actually there are more fields that could be used to assist detection
