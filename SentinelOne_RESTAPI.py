import json
import sys
import urllib.request
import urllib.parse
import time
from datetime import datetime, timedelta
MGMT_URL = ""
TOKEN = ""

def currT():
    return str(datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%S.%f")[:-3])

def getDVevents(queryID):
    RESULTS_DS = []
    # Build relevant strings
    url = MGMT_URL + '/web/api/v2.1/dv/events?queryId={}&limit=1000'.format(queryID)
    headers = {'Authorization': 'APIToken ' + TOKEN}
    
    totalItemsReturned = -1
    items_left = -1

    while (True):
        RES_DS = []
        req = urllib.request.Request(url, method='GET', headers=headers)
        try:
            resp = urllib.request.urlopen(req)
        except Exception as e:
            print(e)
            print(url)
            exit()

        # Retrieve container JSON
        http_json=json.loads(resp.read().decode('utf-8'))
        nextCursor = http_json['pagination']['nextCursor']
        if totalItemsReturned == -1:
            totalItemsReturned = http_json['pagination']['totalItems']
            print("\t[+] {} - QID <{}> - Collecting <{}> Total Results from DVQUERY".format(currT(),queryID,totalItemsReturned))
        
        totalItemsReturned = http_json['pagination']['totalItems']
        DATA  = http_json['data']
        for d in DATA:
            RES_DS.append(d)
        RESULTS_DS+=RES_DS
        if nextCursor == None:
            print("\t[+] {} - QID <{}> - Collected all Results from DVQUERY".format(currT(),queryID))
            return RESULTS_DS
            break
        else:
            print("\t[~] {} - QID <{}> 1000 Events Scraped! - <{}> Total Results from DVQUERY Remain".format(currT(),queryID,totalItemsReturned))
            url = MGMT_URL + '/web/api/v2.1/dv/events?cursor={}&queryId={}&limit=1000'.format(nextCursor,queryID)
    
def getDVqueryStatus(queryID):
    # Build relevant strings
    url = MGMT_URL + '/web/api/v2.1/dv/query-status?queryId={}'.format(queryID)
    headers = {'Authorization': 'APIToken ' + TOKEN}

    # Retrieve container JSON
    progress = 0
    state = ""
    while progress != 100:
        req = urllib.request.Request(url, method='GET', headers=headers)
        try:
            resp = urllib.request.urlopen(req)
        except Exception as e:
            print(e)
            exit()
        a=json.loads(resp.read().decode('utf-8'))
        progress = a['data']['progressStatus']
        state = a['data']['responseState']
        print("\t[~] {} - QID <{}> is <{}> ----- <{}%> COMPLETE".format(currT(),queryID,state,progress))
        time.sleep(DV_SLEEP_INTERVAL)

    return a

def deepVisibility(query,resultsLimit,showAllFields, time_query):
    # Build relevant strings
    url = MGMT_URL + '/web/api/v2.1/dv/init-query'
    timestamps = DVtimeVariables(time_query)
    body = {
            "toDate": timestamps[1].isoformat()+"Z",
            "fromDate": timestamps[0].isoformat()+"Z",
            "query": query,
            "tenant": "true",
            "queryType": ["events"],
            "limit": 1000,
            "isVerbose": showAllFields
    }
    headers = {'Authorization': 'APIToken ' + TOKEN, 'Content-Type' : 'application/json'}

    req = urllib.request.Request(url, headers=headers, method='POST', data=json.dumps(body, sort_keys=True).encode('utf-8'))
    resp = urllib.request.urlopen(req)

    # Retrieve container JSON
    queryID = json.loads(resp.read().decode('utf-8'))['data']['queryId']
    print("[+] {} - DVQuery_EXECUTED:<{}>~QID:<{}>~RESULTS_LIMIT:<{}>~INPUT_TIME_QUERY:<{}>~Search_Window:<{}>--<{}>".format(currT(),queryID,query,resultsLimit,time_query,body['fromDate'],body['toDate']))
    getDVqueryStatus(queryID)
    return getDVevents(queryID)

def quarantineIncident(contentHashes,applyToResolvedIncidents):
    # Build relevant strings
    url = MGMT_URL + '/web/api/v2.1/threats/mitigate/quarantine'
    body = {"filter":{
        "limit":"500",
        "contentHashes" : contentHashes,
        "resolved":applyToResolvedIncidents,
        "tenant":"true"
        },
        "data":{}
    }
    headers = {'Authorization': 'APIToken ' + TOKEN, 'Content-Type' : 'application/json'}
    a = True
    while (a):
        req = urllib.request.Request(url, headers=headers, method='POST', data=json.dumps(body, sort_keys=True).encode('utf-8'))
        resp = urllib.request.urlopen(req)

        # Retrieve container JSON
        data = json.loads(resp.read().decode('utf-8'))
        alertsEffected = data['data']['affected']
        print("[+] {} - {} alerts have been mitigated".format(currT(),alertsEffected))
        if alertsEffected > 0:
            a=True
        else:
            a=False
            
def resolveIncident(contentHashes, siteIDs, applyToResolvedIncidents, incidentStatus, analystVerdict):
    # Build relevant strings
    url = MGMT_URL + "/web/api/v2.1/threats/incident"
    body = {"filter":{
        "limit":"500",
        "siteIds" : siteIDs,
        "contentHashes" : contentHashes,
        "resolved":applyToResolvedIncidents,
        },
        "data":{
            "incidentStatus":incidentStatus,
            "analystVerdict":analystVerdict
        }
    }
    headers = {'Authorization': 'APIToken ' + TOKEN, 'Content-Type' : 'application/json'}
    a = True
    while (a):
        req = urllib.request.Request(url, headers=headers, method='POST', data=json.dumps(body, sort_keys=True).encode('utf-8'))
        resp = urllib.request.urlopen(req)

        # Retrieve container JSON
        data = json.loads(resp.read().decode('utf-8'))
        alertsEffected = data['data']['affected']
        print("[+] {} - {} alerts have been resolved by setting incident status to <{}> and analyst verdict to <{}>".format(currT(),alertsEffected,incidentStatus,analystVerdict))
        if alertsEffected > 0:
            a=True
        else:
            a=False

def DVtimeVariables(time_query):
    currentTime = datetime.utcnow()
    currentTimeFormatted = currentTime
    if len(time_query) == 1:
        if "h" in time_query[0]:
            startingTime = currentTime - timedelta(hours=int(time_query[0][:-1]))
            return [startingTime, currentTime]
        elif "d" in time_query[0]:
            startingTime = currentTime - timedelta(hours=24*int(time_query[0][:-1]))
            #start,end
            return [startingTime, currentTime]
    else:
        if type(time_query) == list():
            return time_query
        else:
            print("[-] {} - timevar fail".format(currT()))
            exit()
        #To and From query

def returnDefaultIOCObject(source_file):
    if "\\" in source_file:
        source = source_file.split("\\")[-1].split(".")[0]
    else:
        source = source_file.split(".")[0]
    time = datetime.now()
    default_ttl = time + timedelta(hours=24*90)
    return {"source":source, "name":source, "externalId": "N/A", "type": "N/A", "value": "N/A", "method":"EQUALS", "description": "N/A", "validUntil":str(default_ttl.isoformat())}

def cti_data_builder(row):

    row_split = row.split(",",2)
    keys = {"Domain":"DNS", "Email":"N/A", "FileHash-MD5":"MD5", "FileHash-SHA1":"SHA1", "FileHash-SHA256":"SHA256", "IPv4":"IPV4", "IPv6":"IPV6", "URL": "URL"}
    results = {"type":keys[row_split[0]], "value":row_split[1], "description":row_split[2].replace('"',"").replace("'","")}
    return results

def ingestThreatIntelligence(flatfile,account_id):
    cti_data = ingest_ioc_flatfile(flatfile)
    # Build relevant strings
    url = MGMT_URL + '/web/api/v2.1/threat-intelligence/iocs'
    data_list = []
    body = {"filter":{
        "accountIds" : [account_id],
        "tenant":"true"},
        "data":data_list
    }
    headers = {'Authorization': 'apiToken ' + TOKEN, 'Content-Type' : 'application/json'}

    for entry in cti_data:
        ingest_results = cti_data_builder(entry)
        if ingest_results['type'] == "N/A":
            continue
        data_payload = returnDefaultIOCObject(flatfile)
        data_payload.update(ingest_results)
        data_list.append(data_payload)
    

    a = json.dumps(body, sort_keys=True)

    re = a.encode('utf-8')

    req = urllib.request.Request(url, headers=headers, method='POST', data=re)
    resp = urllib.request.urlopen(req)

    # Retrieve container JSON
    data = json.loads(resp.read().decode('utf-8'))

    alertsEffected = len(data['data'])
    print("Added IOC <{}> sources <{}> for accountID <{}>".format(alertsEffected,flatfile,account_id))

def deleteThreatIntelligence(account_id,IOC_value):
    url = MGMT_URL + '/web/api/v2.1/threat-intelligence/iocs'
    data_list = []
    body = {"filter":{
        "accountIds" : [account_id],
        "tenant":"true",
        "value":IOC_value
    }
    }
    headers = {'Authorization': 'apiToken ' + TOKEN, 'Content-Type' : 'application/json'}
    
    #data = urllib.parse.urlencode(body).encode()

    a = json.dumps(body, sort_keys=True)

    re = a.encode('utf-8')

    req = urllib.request.Request(url, headers=headers, method='DELETE', data=re)
    resp = urllib.request.urlopen(req)

    # Retrieve container JSON
    data = json.loads(resp.read().decode('utf-8'))

    alertsEffected = data['data']['affected']
    print("Deleted {} IOCs that had a value of <{}> for accountID <{}>".format(alertsEffected,IOC_value,account_id))

def ingest_ioc_flatfile(file_name):
    infile = open(file_name, 'r').readlines()

    infile.pop(0)

    rows = []

    for a in infile:
        a = rows.append(a.strip("\n"))
    return rows

def dump_site_ids_for_accountid(accountId):
    url = MGMT_URL + '/web/api/v2.1/sites?accountId={}&limit=1000'.format(accountId)
    headers = {'Authorization': 'apiToken ' + TOKEN, 'Content-Type' : 'application/json'}
    req = urllib.request.Request(url, headers=headers, method='GET')
    resp = urllib.request.urlopen(req)

    # Retrieve container JSON
    data = json.loads(resp.read().decode('utf-8'))
    return data['data']['sites']

def get_site_ids():
    accountID = ""
    accountID2 = ""
    siteIds = []
    siteIds += dump_site_ids_for_accountid(accountID)
    siteIds += dump_site_ids_for_accountid(accountID2)

    all_site_ids = []

    for entry in siteIds:
        all_site_ids.append(entry['id'])

    return all_site_ids

def get_agents(siteId):
    RESULTS_DS = []
    url = MGMT_URL + '/web/api/v2.1/agents?siteIds={}&limit=1000'.format(siteId)
    headers = {'Authorization': 'apiToken ' + TOKEN, 'Content-Type' : 'application/json'}

    totalItemsReturned = -1
    items_left = -1

    while (True):
        RES_DS = []
        req = urllib.request.Request(url, method='GET', headers=headers)
        try:
            resp = urllib.request.urlopen(req)
        except Exception as e:
            print(e)
            print(url)
            exit()

        # Retrieve container JSON
        http_json=json.loads(resp.read().decode('utf-8'))
        nextCursor = http_json['pagination']['nextCursor']
        if totalItemsReturned == -1:
            totalItemsReturned = http_json['pagination']['totalItems']
        
        totalItemsReturned = http_json['pagination']['totalItems']
        DATA  = http_json['data']
        for d in DATA:
            RES_DS.append(d)


        RESULTS_DS+=RES_DS
        if nextCursor == None:
            return RESULTS_DS
        else:
            url = MGMT_URL + "/web/api/v2.1/agents?siteIds={}&cursor='{}'&limit=1000".format(siteId,nextCursor)

def dump_agent_data(agent_payload):

    try:
        ad_data = agent_payload['activeDirectory']
    except:
        ad_data = {}

    try:
        print("{}~{}~{}~{}~{}~{}~{}~{}~{}~{}".format(agent_payload['computerName'],agent_payload['siteName'],agent_payload['lastActiveDate'],agent_payload['lastIpToMgmt'],agent_payload['externalIp'],agent_payload['osType'],agent_payload['machineType'],agent_payload['siteId'],agent_payload['uuid'],ad_data))
    except:
        try:
            print("[ERROR-SpecialChars]~{}~{}~{}~{}~{}~{}~{}~{}~{}".format(agent_payload['siteName'],agent_payload['lastActiveDate'],agent_payload['lastIpToMgmt'],agent_payload['externalIp'],agent_payload['osType'],agent_payload['machineType'],agent_payload['siteId'],agent_payload['uuid'],ad_data))
        except:
            try:
                print("{}~{}~{}~{}~{}~{}~{}~{}~{}~[ERROR-SpecialChars]".format(agent_payload['computerName'],agent_payload['siteName'],agent_payload['lastActiveDate'],agent_payload['lastIpToMgmt'],agent_payload['externalIp'],agent_payload['osType'],agent_payload['machineType'],agent_payload['siteId'],agent_payload['uuid']))
            except:
                print("[ERROR-SpecialChars]~{}~{}~{}~{}~{}~{}~{}~{}~[ERROR-SpecialChars]".format(agent_payload['siteName'],agent_payload['lastActiveDate'],agent_payload['lastIpToMgmt'],agent_payload['externalIp'],agent_payload['osType'],agent_payload['machineType'],agent_payload['siteId'],agent_payload['uuid']))

def dump_all_agents():
    sites = get_site_ids()
    for s in sites:
        agents = get_agents(s)
        #print("{} - {} ID is complete".format(currT(),s))
        if len(agents) == 0:
            continue
        for a in agents:
            dump_agent_data(a)
        time.sleep(10)

def get_installed_applications(SITE_ID):
    # Build relevant strings
    url = MGMT_URL + '/web/api/v2.0/installed-applications?siteIds=' + SITE_ID + '&limit=1000'
    headers = {'Authorization': 'APIToken ' + TOKEN}
    req = urllib.request.Request(url, headers=headers)
    resp = urllib.request.urlopen(req)

    # Retrieve container JSON
    data = json.loads(resp.read().decode('utf-8'))

    # Extract data JSON
    data2 = data['data']
    pagination = data['pagination']

    # Loop while last_id is not NULL
    while True:
        for i in data2:
            try:
                print(str(i['agentComputerName']) + "~" +
                        str(i['createdAt']) + "~" +
                        str(i['id']) + "~" +
                        str(i['installedAt']) + "~" +
                        str(i['name']) + "~" +
                        str(i['osType']) + "~" +
                        str(i['publisher']) + "~" +
                        str(i['riskLevel']) + "~" +
                        str(i['signed']) + "~" +
                        str(i['size']) + "~" +
                        str(i['type']) + "~" +
                        str(i['updatedAt']) + "~" +
                        str(i['version'])
                )
            except:
                a=str(i['agentComputerName'])

        if not pagination['nextCursor']:
            break

        # Request next batch of data
        url = MGMT_URL + '/web/api/v2.0/installed-applications?cursor=' + pagination['nextCursor']
        req = urllib.request.Request(url, headers=headers)
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read().decode('utf-8'))
        data2 = data['data']
        pagination = data['pagination']

def grab_apps_for_site_ids(SITE_IDs):
    print("agentComputerName~"
            "createdAt~"
            "id~"
            "installedAt~"
            "name~"
            "osType~"
            "publisher~"
            "riskLevel~"
            "signed~"
            "size~"
            "type~"
            "updatedAt~"
            "version"+"\n"                                   
        )

    for id in SITE_IDs:
        get_installed_applications(id)  


'''
#dump_all_agents()
for accountID in account_ids:
    ingestThreatIntelligence("IOC.csv", accountID)  
    time.sleep(10)

things_to_delete = ["12.30.50.20", "vague.com"]

for thing in things_to_delete:
    for accountID in account_ids:
        deleteThreatIntelligence(accountID,thing)
        time.sleep(5)

resolveIncident(threatHashes,siteIDs,"false","resolved","false_positive")
#quarantineIncident(threatHashes, "true")

#getDVevents('q1111111111111111111',1000)

DV_SLEEP_INTERVAL = 5
DV_MAX_RESULTS = 20000
DV_RESULT_PARAM = 20000
DV_QUERY = 'SrcProcDisplayName = "Microsoft(C) Register Server" AND Not  SrcProcImagePath In AnyCase ( "C:\WINDOWS\SysWOW64\regsvr32.exe", "C:\Windows\system32\regsvr32.exe")'
DV_SHOW_ALL_FIELDS = "false" #priorities fields is false
DV_SEARCH_QUERY = ['7d']

if DV_RESULT_PARAM > DV_MAX_RESULTS:
    DV_RESULT_PARAM = DV_MAX_RESULTS


#deepVisibility('SrcProcCmdLine RegExp ".*(javascript|mshtml|runhtmlapplication).*"', 1000, "false", ["1h"])
#deepVisibility(DV_QUERY, DV_RESULT_PARAM, DV_SHOW_ALL_FIELDS, DV_SEARCH_QUERY)
'''