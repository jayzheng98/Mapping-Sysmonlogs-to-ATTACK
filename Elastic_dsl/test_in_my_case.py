import csv
from elasticsearch import Elasticsearch
import json
import re
from pandas import DataFrame
import datetime

# The specific index name in ELK. You can use wildcard "*" here as well
index1 = 'test-2023.01.16'

tactic_list = ['collection.csv', 'command and control.csv', 'credential access.csv', 'defense evasion.csv',
               'discovery.csv', 'execution.csv', 'exfiltration.csv', 'impact.csv',
               'lateral-movement.csv', 'multiple.csv', 'persistence.csv', 'privilege escalation.csv']

def es_search(dsl_term, index_term):
    es = Elasticsearch()
    result = es.search(index=index_term, body=dsl_term, size=300)
    log_list = json.dumps(result["hits"]["hits"], indent=2, ensure_ascii=False)
    log_list = json.loads(log_list)  # Change to "list" format
    return log_list

# Mapping sysmonlogs to ATT&CK techniques
def log_labeling():
    output = {}
    for file in tactic_list:
        with open(file, 'r', encoding='utf-8-sig') as dsl_list:
            row = csv.reader(dsl_list)
            for each in row:
                dsl = eval(each[1])  # Transform the dsl query sentences into "dict" format
                logs = es_search(dsl, index1)  # Execute queries, the output is a "list" of "dicts"

                for log in logs:
                    try:
                        if output[log['_id']]:
                            output[log['_id']].append(each[0])
                    except:
                        output[log['_id']] = []
                        output[log['_id']].append(each[0])
    return output  # {'_id1' : [technique_id1, technique_id3], '_id2' : [technique_id2],...}

# Fetch all logs in a index and export them to a csv file
def fetch_all(index_term, labelled_logs):
    es = Elasticsearch()
    query = es.search(index=index_term, scroll='5m', size=100)
    results = query['hits']['hits']
    total = query['hits']['total']['value']
    scroll_id = query['_scroll_id']

    for i in range(0, int(total / 100) + 1):
        query_scroll = es.scroll(scroll_id=scroll_id, scroll='5m')['hits']['hits']
        results += query_scroll

    with open('../syslog_source/syslog.csv', 'w', newline='', encoding='utf-8') as f:
        # Fields of syslog that we want to write into csv file as headers
        headers = ['_key', '_id', 'CommandLine', 'EventTime', 'LocalIP', '@timestamp', 'AccountType', 'CallTrace',
                   'Category', 'Channel', 'CreationUtcTime', 'CurrentDirectory', 'Description', 'EventID',
                   'EventReceivedTime', 'EventType', 'ExecutionProcessID', 'ExecutionThreadID', 'GrantedAccess',
                   'Hashes', 'Hostname', 'Image', 'ImageLoaded', 'IntegrityLevel', 'Keywords', 'LevelValue',
                   'log_from', 'LogonGuid', 'OpcodeValue', 'OriginalFileName', 'ParentCommandLine', 'ParentImage',
                   'ParentProcessGuid', 'ParentProcessId', 'ParentProcessID', 'ParentUser', 'port', 'ProcessGuid',
                   'ProcessID', 'ProviderGuid', 'RecordNumber', 'RuleName', 'SchemaVersion', 'Severity',
                   'SeverityValue', 'Signature', 'SignatureStatus', 'Signed', 'SourceImage', 'SourceModuleName',
                   'SourceName', 'SourceProcessGUID', 'SourceProcessId', 'SourceThreadId', 'SourceUser',
                   'SyslogFacility', 'SyslogFacilityValue', 'SyslogSeverity', 'SyslogSeverityValue', 'TargetFilename',
                   'TargetImage', 'TargetObject', 'TargetProcessGUID', 'TargetProcessId', 'TargetUser', 'Task',
                   'TaskValue', 'TerminalSessionId', 'ThreadID', 'User', 'UserID', 'Version', 'RiskLevel']
        count = 0
        d = {}

        # Every value in dict "d" is a "list"
        for i, name in enumerate(headers):
            d[name] = []

        for count1, res in enumerate(results):
            # Unify Linux's "EventTime"
            if res['_source']['Channel'][0] == 'L':
                a = datetime.datetime.strptime(res['_source']['EventTime'][:18], "%Y-%m-%dT%H:%M:%S")
                res['_source']['EventTime'] = a

            d[headers[0]].append(count1+1)
            try:
                if res['_source']['RuleName'] != '-':
                    res['_source']['RiskLevel'] = 1
                    temp = re.findall(r"id=(.+?),", res['_source']['RuleName'], flags=re.IGNORECASE)
                    if temp:
                        if temp[0] == 'Port Monitors':
                            temp[0] = 'T1547.010'
                        res['_source']['RuleName'] = temp
                else:
                    res['_source']['RiskLevel'] = 0
            except:
                res['_source']['RuleName'] = '-'
                res['_source']['RiskLevel'] = 0

            # Precise matching (Rewrite the "RuleName" and "RiskLevel" of some logs)
            if count < len(labelled_logs):  # If all elements in "labelled_logs" have been matched, skip this process
                for key, value in labelled_logs.items():
                    if res['_id'] == key:
                        count += 1
                        res['_source']['RuleName'] = value
                        res['_source']['RiskLevel'] = 2

            # Construct the dict "d" for the exporting into csv
            d[headers[1]].append(res[headers[1]])
            for i in range(2, len(headers)):
                try:
                    d[headers[i]].append(res['_source'][headers[i]])
                except:
                    d[headers[i]].append(None)

        # Output to "syslog.csv"
        output = DataFrame(d, columns=headers)
        output.to_csv(f, header=True, index=False, encoding='utf-8')

if __name__ == '__main__':
    labelled_logs = log_labeling()
    fetch_all(index1, labelled_logs)
