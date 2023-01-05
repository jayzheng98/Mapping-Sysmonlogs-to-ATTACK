import csv
from elasticsearch import Elasticsearch
import json
import re
from pandas import DataFrame


index1 = 'test-2022.12.15'

tactic_list = ['collection.csv', 'command and control.csv', 'credential access.csv', 'defense evasion.csv',
             'discovery.csv', 'execution.csv', 'exfiltration.csv', 'impact.csv',
             'lateral-movement.csv', 'multiple.csv', 'persistence.csv', 'privilege escalation.csv']

def es_search(dsl_term, index_term):
    es = Elasticsearch()
    result = es.search(index=index_term, body=dsl_term, size=300)
    log_list = json.dumps(result["hits"]["hits"], indent=2, ensure_ascii=False)
    log_list = json.loads(log_list)  # 转换成列表
    return log_list

def log_labeling():
    output={}
    for file in tactic_list:
        with open(file, 'r', encoding='utf-8-sig') as dsl_list:  # encoding='utf-8'
            row = csv.reader(dsl_list)
            for each in row:
                dsl = eval(each[1])  # 将dsl语句转换为字典
                logs = es_search(dsl, index1)  # 执行搜索，返回匹配结果（列表里嵌套字典）

                for log in logs:
                    try:
                        if output[log['_id']]:
                            output[log['_id']].append(each[0])
                    except:
                        output[log['_id']]=[]
                        output[log['_id']].append(each[0])
    return output

def fetch_all(index_term, labelled_logs):
    es = Elasticsearch()
    query = es.search(index=index_term, scroll='5m', size=100)
    results = query['hits']['hits']  # es查询出的结果第一页
    total = query['hits']['total']['value']  # es查询出的结果总量
    scroll_id = query['_scroll_id']  # 游标用于输出es查询出的所有结果

    for i in range(0, int(total / 100) + 1):
        query_scroll = es.scroll(scroll_id=scroll_id, scroll='5m')['hits']['hits']
        results += query_scroll

    with open('syslog.csv', 'w', newline='', encoding='utf-8') as f:
        header = ['_id', 'CommandLine', 'EventTime', 'LocalIP', '@timestamp', 'AccountType', 'CallTrace',
                  'Category', 'Channel', 'CreationUtcTime', 'CurrentDirectory', 'Description', 'EventID',
                  'EventReceivedTime', 'EventType', 'ExecutionProcessID', 'ExecutionThreadID', 'GrantedAccess',
                  'Hashes', 'Hostname', 'Image', 'ImageLoaded', 'IntegrityLevel', 'Keywords', 'LevelValue',
                  'log_from', 'LogonGuid', 'OpcodeValue', 'OriginalFileName', 'ParentCommandLine', 'ParentImage',
                   'ParentProcessGuid', 'ParentProcessId', 'ParentProcessID',
                  'ParentUser', 'port', 'ProcessGuid', 'ProcessID', 'ProviderGuid', 'RecordNumber', 'RuleName',
                  'SchemaVersion', 'Severity', 'SeverityValue', 'Signature', 'SignatureStatus', 'Signed', 'SourceImage',
                  'SourceModuleName', 'SourceName', 'SourceProcessGUID', 'SourceProcessId', 'SourceThreadId',
                  'SourceUser', 'SyslogFacility', 'SyslogFacilityValue', 'SyslogSeverity',
                  'SyslogSeverityValue', 'TargetFilename', 'TargetImage', 'TargetObject', 'TargetProcessGUID',
                  'TargetProcessId', 'TargetUser', 'Task', 'TaskValue','TerminalSessionId', 'ThreadID', 'User',
                  'UserID',  'Version', 'RiskLevel']
        count = 0
        d = {}
        for i, name in enumerate(header):
            d[name] = []

        for res in results:
            try:
                if(res['_source']['RuleName'] != '-'):
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

            # Precise matching
            if count < len(labelled_logs):    # If all elements in "labelled_logs" have been matched, skip this process
                for key, value in labelled_logs.items():
                    if res['_id'] == key:
                        count += 1
                        res['_source']['RuleName'] = value
                        res['_source']['RiskLevel'] = 2

            # Rewrite a dict for csv
            d[header[0]].append(res[header[0]])
            for i in range(1, len(header)):
                try:
                    if(res['_source'][header[i]]!=None):
                        d[header[i]].append(res['_source'][header[i]])
                    else:
                        d[header[i]].append(None)
                except:
                    d[header[i]].append(None)

        # Output to "syslog.csv"
        output = DataFrame(d, columns=header)
        output.to_csv(f, header=True, index=False, encoding='utf-8')

if __name__ == '__main__':
    labelled_logs =log_labeling()
    fetch_all(index1, labelled_logs)
