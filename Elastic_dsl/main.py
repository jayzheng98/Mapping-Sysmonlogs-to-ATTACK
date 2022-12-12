import csv
from elasticsearch import Elasticsearch
import json
import datetime

now_date = datetime.datetime.now().strftime('%Y.%m.%d')
print(now_date)
index = 'test*'

def es_search(dsl_term, index_term):
    es = Elasticsearch()
    result = es.search(index=index_term, body=dsl_term, size=300)
    log_list = json.dumps(result["hits"]["hits"], indent=2, ensure_ascii=False)  
    log_list = json.loads(log_list)      # Convert to list
    return log_list

with open('discovery.csv', 'r',encoding='utf-8') as dsl_list_1: # ,encoding='utf-8'
    row = csv.reader(dsl_list_1)
    for each in row:
        print('\n', each[0], ':', count)
        dsl = eval(each[1])  
        logs = es_search(dsl, index)      # Return matching results (format: dictionary nested in the list)

        for log in logs:
            print(log['_source']['EventTime'])
            try:
                print('CommandLine: ',log['_source']['CommandLine'])
            except:
                try:
                    print('TargetFilename: ', log['_source']['TargetFilename'])
                except:
                    print('Image:', log['_source']['Image'])

