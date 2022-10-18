import logging
import json
import requests
import azure.functions as func
import os
import adal
from pytz import timezone
from datetime import datetime
import time

#TODO: 모듈 분리
#TODO: 로직앱으로 트리거 받는 부분 제외하고 싹 다 클래스로 만들기
init_num = 2001

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    #로직앱에서 트리거 된 변수 값  가져오기
    req_body = req.get_json()

    nsg_id = req_body['NSG']
    dst_ip = req_body['privateIP']
    dst_port = req_body['dst_port']
    src_ip = req_body['src_ip']
    protocol = req_body['protocol']

    logging.info('GET parameters from Logic Apps.')
    logging.info('nsg_id : %s, dst_ip : %s, dst_port : %s, src_ip : %s, protocol: %s',nsg_id,dst_ip,dst_port,src_ip,protocol)

    bearer_token = post_ad_access_token()

    URL = f"https://management.azure.com{nsg_id}/securityRules?api-version=2020-05-01"
    origin_NSG_Rules = GET_NSG_Rule_List(URL,bearer_token)     #NSG Rule 목록 가져오기

    modified_NSG_Rules = sort_NSG_List(origin_NSG_Rules)    #데이터 구조 변형

    rule_name, r_JSON = update_or_append_a_rule(modified_NSG_Rules, dst_ip, src_ip, dst_port, protocol) #규칙 수정, 추가 여부 판단

    if not r_JSON :
        pass
    else :
        if rule_name:
            URL = f"https://management.azure.com{nsg_id}/securityRules/{rule_name}?api-version=2020-05-01"
            logging.info('NSG Rule will be updated.')
        else:
            time = datetime.now(timezone('Asia/Seoul')).strftime('%Y-%m-%dT%H:%M:%S')
            URL = f"https://management.azure.com{nsg_id}/securityRules/MDCAutomation_src_{src_ip}_dst_{dst_ip}_{dst_port}_{protocol}_deny_{time}?api-version=2020-05-01"
            logging.info('NSG Rule will be created.')
        
        result = PUT_NSG_Rule(URL, bearer_token, r_JSON)

    #* 로직앱에 던져 줄 값 : 상태 코드, 수정 및 생성 된 규칙 내용
    if result and r_JSON :
        return func.HttpResponse(
            "This HTTP triggered function executed. Check status_code.",
            status_code=result #, body=r_JSON
        )
        exit()

#* 액세스 토큰 받아오기
def post_ad_access_token():
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]

    authentication_endpoint = 'https://login.microsoftonline.com/'
    resource  = 'https://management.core.windows.net/'

    context = adal.AuthenticationContext(authentication_endpoint + tenant_id)
    token_response = context.acquire_token_with_client_credentials(resource, client_id, client_secret)

    access_token = token_response.get('accessToken')

    if not access_token:
        logging.info('Failed to get Access token from Azure.')
    else : 
        logging.info('Access token received from Azure successfully.')

    return access_token

#* REST로 GET 요청
def GET_NSG_Rule_List(url, token):
    logging.info('Try to GET NSG Rules from => %s',url)
    headers = {'Content-Type': 'application/json', 'Authorization':"Bearer "+token, 'Host':'management.azure.com'}
    
    response = requests.get(url, verify=False, headers=headers)    
    json_data = response.json()
    JSON = json_data["value"]
    logging.info('GET NSG rule list successfully.')

    return JSON

#* NSG 규칙 목록 재구성 & 정렬
def sort_NSG_List(raw_data):

    for rule in raw_data:
        property = rule["properties"]
        rule.pop("properties")
        rule.pop("etag")
        rule.pop("type")
        for key in property:
            rule[key] = property[key]
    logging.info('Modify NSG rule list successfully.')

    sorted_data = sorted(raw_data, key=lambda x:x["priority"])
    logging.info('Sort NSG rule list successfully.')

    return sorted_data

#* NSG 규칙 수정해야하는지, 새로 추가해야하는지 판단
def update_or_append_a_rule(NSG_Rules, private_IP, src_ip, dst_port, protocol):
    for rule in NSG_Rules:
        #Inbound Deny rule이 아니면 다음 rule으로 넘어감
        if rule["direction"] != "Inbound" or rule["access"] != "Deny" : 
            continue

        #프로토콜이 ALL 또는 위협 IP의 프로토콜과 같지 않으면 다음 rule으로 넘어감
        if rule["protocol"] != "*" and rule["protocol"] != protocol :
            continue 

        #dst_ip, dsp_port, src_ip 체크 메소드 결과를 확인 
        bool1, DST_IP = check_dst_ip(rule, private_IP) 
        bool2, DST_PORT = check_dst_port(rule, dst_port) 
        bool3, SRC_IP = check_src_ip(rule, src_ip)

        #셋 중 하나라도 값(True)이 있으면 => rule을 수정
        if bool1 or bool2 or bool3:
            return rule["name"], write_JSON(DST_IP, DST_PORT, SRC_IP, rule["priority"], rule["protocol"]) 
        else: #새로운 rule 추가
            continue

    name = f"MDCAutomation_src_{src_ip}_{private_IP}_ALL_ALL_deny_ 시간"
    return None, write_JSON(private_IP, dst_port, src_ip, search_unoccupied_priority(NSG_Rules), "*")
    #?이미 같은 룰이 있는데 보안 경고가 울린 경우는?? 이 경우도 고려해야할지?       

#* Destination IP Address 체크
def check_dst_ip(rule, private_IP):
    try:
        if rule["destinationAddressPrefix"] : #destination IP Address에 값이 있는 경우  
            if rule["destinationAddressPrefix"] == "*" : #범위가 all IP인 경우
                return False, rule["destinationAddressPrefix"]
            
            if rule["destinationAddressPrefix"] == private_IP : #private_IP를 포함하는 경우
                return False, rule["destinationAddressPrefix"]
            
            rule["destinationAddressPrefixes"].append(rule["destinationAddressPrefix"])
            rule["destinationAddressPrefixes"].append(private_IP)
            return True, rule["destinationAddressPrefixes"] #기존 string ip를 리스트에 합쳐야할 경우  
    except KeyError:
        logging.warning('"destinationAddressPrefix" does not exist.')

    try:
        if rule["destinationAddressPrefixes"]:  #destination IP Address 리스트에 값이 있는 경우
            if private_IP in rule["destinationAddressPrefixes"] :  #범위에 private_IP를 포함하는 경우
                return False, rule["destinationAddressPrefixes"]
            
            rule["destinationAddressPrefixes"].append(private_IP)
            return True, rule["destinationAddressPrefixes"] #리스트에 ip를 추가해야할 경우
    except KeyError:
        logging.warning('"destinationAddressPrefixes" does not exist.') #문자열, 리스트 둘 중 하나는 반드시 값이 있음. 

#* Destination Port 체크
def check_dst_port(rule, dst_port):
    try:
        if rule["destinationPortRange"] : #destination Port에 값이 있는 경우
            if rule["destinationPortRange"] == "*" : #all port인 경우
                return False, rule["destinationPortRange"]

            if port_check(rule["destinationPortRange"], dst_port): #dst_port를 포함하는지 확인
                return False, rule["destinationPortRange"]
            
            rule["destinationPortRanges"].append(rule["destinationPortRange"])
            rule["destinationPortRanges"].append(dst_port)
            return True, rule["destinationPortRanges"] #기존 port를 리스트에 합쳐야할 경우
    except KeyError:
        logging.warning('"destinationPortRange" does not exist.')

    try:
        if rule["destinationPortRanges"]:  #destination Port 리스트에 값이 있는 경우
            for port_string in rule["destinationPortRanges"]: #여러 범위들 중 dst_port가 포함되어 있는지 확인
                if port_check((port_string), dst_port):
                    return False, rule["destinationPortRanges"]
                
            rule["destinationPortRanges"].append(dst_port)
            return True, rule["destinationPortRanges"] #리스트에 port를 추가해야할 경우
    except KeyError:
        logging.warning('"destinationPortRanges" does not exist.')

#* Source IP Address 체크
def check_src_ip(rule, src_ip):
    try: #규칙에서 찾는 인덱스가 없을 수 있음
        if rule["sourceAddressPrefix"] : #source IP Address에 값이 있는 경우
            if rule["sourceAddressPrefix"] == "*" : #범위가 all IP인 경우
                return False, rule["sourceAddressPrefix"]
            
            if type(src_ip) is str and rule["sourceAddressPrefix"] == src_ip : #src_IP를 포함하는 경우
                return False, rule["sourceAddressPrefix"]
            
            rule["sourceAddressPrefixes"].append(rule["sourceAddressPrefix"])
            if type(src_ip) is str:
                rule["sourceAddressPrefixes"].append(src_ip)
            if type(src_ip) is list: 
                rule["sourceAddressPrefixes"].extend(src_ip)
                
            return True, rule["sourceAddressPrefixes"] #기존 string ip를 리스트에 합쳐야할 경우   
    except KeyError:
        logging.warning('"sourceAddressPrefix" does not exist.')
    
    try:
        if rule["sourceAddressPrefixes"]: #source IP Address 리스트에 값이 있는 경우
            if type(src_ip) is str :
                if src_ip in rule["sourceAddressPrefixes"] : #범위에 단수 src_IP를 포함하는 경우
                    return False, rule["destinationAddressPrefixes"]
                else :
                    rule["sourceAddressPrefixes"].append(src_ip)
                    return True, rule["sourceAddressPrefixes"]
            if type(src_ip) is list: #범위에 복수 src_IP를 포함하는 경우
                set_a = set(src_ip)
                set_b = set(rule["sourceAddressPrefixes"])
                result_set = set_a - set_b
                if not result_set:
                    return False, rule["sourceAddressPrefixes"]
                rule["sourceAddressPrefixes"].extend(result_set)
                return True, rule["sourceAddressPrefixes"] #리스트에 ip를 추가해야할 경우
    except KeyError:
        logging.warning('"sourceAddressPrefixes" does not exist.')

#* NSG규칙 수정 및 생성 
def PUT_NSG_Rule(url, token, JSON):
    headers = {'Content-Type': 'application/json', 'Authorization': "Bearer " + token}
    response = requests.put(url, headers=headers, data=json.dumps(JSON))

    if response.status_code == 200:
        logging.info("Update a NSG Rule successfully.")
    elif response.status_code == 201:
        logging.info("Create a NSG Rule successfully.")
    else :
        logging.error("PUT a NSG Rule failed.")
        
    return response.status_code

#* 포트 범위 인지, 포트 번호만 있는지 확인 후 포트가 포함되었는지까지 확인
def port_check(port_string, port):
    if '-' in port_string: #포트 범위
        return port_in_range(port_string, port)
    elif port_string == port: #포트 번호
        return False

#* 포트 범위 쪼개고, 정수로 변환
def port_in_range(port_range, port):    
    port_list = port_range.split('-')   #문자열 split

    if port in range(int(port_list[0]), int(port_list[1])): #정수로 변환 -> 범위 내에 포트가 포함됐는지 확인
        return False
    else:
        return True

#* 미사용 우선순위 번호 찾기
def search_unoccupied_priority(rules):
    global init_num
    p_list = []

    for i in range(len(rules)):
        if rules[i]["priority"] < init_num:     #2000이하 규칙은 무시
            continue

        if rules[-1]["priority"] - rules[i]["priority"] + 1 == len(rules):  #2000이상 우선순위가 비어있지 않고 연속하는 경우
            break

        if i < len(rules):
            forth_num = rules[i]["priority"]
            back_num = rules[i+1]["priority"]
            p_list = list(range(forth_num, back_num)) #연속하는 두 규칙의 우선순위 값들 사이 비어있는 값 확인

            if len(p_list) < 2 : 
                continue
            else:
                return p_list[0]       #비어있는 우선순위 발견

    if not p_list :
        return rules[-1]["priority"]+1      #빈 번호가 없다면, 존재하는 규칙 중 가장 마지막 우선순위+1 값 리턴

#* NSG Rule json 작성
def write_JSON(dst_ip, dst_port, src_ip, priority, protocol):
    JSON = {
        "properties": {
            "access" : "Deny",
            "direction" : "Inbound",
            "sourcePortRange" : "*",
            "priority" : priority,
            "protocol" : protocol 
        }
    }

    if type(src_ip) is list :
        JSON['properties']['sourceAddressPrefixes'] =src_ip
    else :
        JSON ['properties']['sourceAddressPrefix'] =src_ip


    if type(dst_ip) is list :
        JSON['properties']['destinationAddressPrefixes'] =dst_ip
    else : 
        JSON['properties']['destinationAddressPrefix'] =dst_ip
    

    if type(dst_port) is list :
        JSON['properties']['destinationPortRanges'] = dst_port
    else :
        JSON['properties']['destinationPortRange'] =dst_port

    logging.info('%s',str(JSON))

    return JSON