import logging
import requests
import azure.functions as func
import os
import adal
#TODO: 모듈 분리

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    #로직앱에서 트리거 된 변수 값  가져오기
    #NSG = req.params.get('NSG')
    #resourceID = req.params.get('resourceID')
    #attacker_IP_info = req.params.get('table') 
    #private_IP = req.params.get('privateIP')
    #?필요한 string을 묶어서 Dictionary로 사용하는게 더 효율적일듯 

    #!로컬 테스트를 위해서 임시로 값 설정
    NSG = "/subscriptions/c79dd4b6-6951-4546-8573-0b6f972e072d/resourceGroups/brueforce/providers/Microsoft.Network/networkSecurityGroups/target-nsg"
    resourceID = "/subscriptions/c79dd4b6-6951-4546-8573-0b6f972e072d/resourcegroups/brueforce/providers/microsoft.compute/virtualMachines/target"
    private_IP = "10.1.0.5"
    dst_port = "8081"
    src_ip = "111.19.141.80"
    protocol = "TCP"

    #TODO: 생각해보니까..... src_ip가 리스트인거 고려 안했다
    #TODO: 로직앱에서 파라미터 받았을때만 동작하도록

    if not NSG: #NSG가 NULL 값인지 확인
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            NSG = req_body.get('NSG')

    #TODO: 로직앱으로 트리거 받는 부분 제외하고 싹 다 클래스로 만들기~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    bearer_token = post_ad_access_token()

    #NSG Rule 목록 가져오기
    URL = f"https://management.azure.com{NSG}/securityRules?api-version=2020-05-01"
    origin_NSG_Rules = GET_NSG_Rule_List(URL,bearer_token)

    modified_NSG_Rules = sort_NSG_List(origin_NSG_Rules)

    # #VM 정보 가져오기 - #?이거 왜 필요한지 모르겠음
    # URL = f"https://management.azure.com{resourceID}/?api-version=2019-12-01"
    # vm = GET_NSG_Rule_List(URL, resourceID, bearer_token)

    result, r_JSON = update_or_append_a_rule(modified_NSG_Rules, private_IP, dst_port, src_ip, protocol)

    if result : #규칙 수정
        update_NSG_Rule(bearer_token, r_JSON)
    else : #규칙 새로 생성
        create_NSG_Rule(bearer_token, r_JSON)

    #TODO:로직앱에 던져 줄 값#####################################################################
    '''
    (1)수정, 생성 된 규칙 내용 -> 메일에 써야되니까
    '''
    if NSG:
        return func.HttpResponse(f"{NSG}", status_code=201)
    else:
        return func.HttpResponse(
            "This HTTP triggered function executed successfully. Pass a NSG in the query string or in the request body for a personalized response.",
            status_code=200
        )

#*액세스 토큰 받아오기
def post_ad_access_token():
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]

    authentication_endpoint = 'https://login.microsoftonline.com/'
    resource  = 'https://management.core.windows.net/'

    context = adal.AuthenticationContext(authentication_endpoint + tenant_id)
    token_response = context.acquire_token_with_client_credentials(resource, client_id, client_secret)

    access_token = token_response.get('accessToken')

    return access_token

#*REST로 GET 요청
def GET_NSG_Rule_List(URL, bearer_token):
    headers = {'Content-Type': 'application/json', 'Authorization':"Bearer "+bearer_token, 'Host':'management.azure.com'}
    res = requests.get(URL, headers=headers)
    json_data = res.json()
    JSON = json_data["value"]

    return JSON

#*NSG 규칙 목록 재구성 & 정렬
def sort_NSG_List(raw_data):
    for rule in raw_data:
        property = rule["properties"]
        rule.pop("properties")
        rule.pop("etag")
        rule.pop("type")
        for key in property:
            rule[key] = property[key]

    sorted_data = sorted(raw_data, key=lambda x:x["priority"])

    return sorted_data

#*NSG 규칙 수정해야하는지, 새로 추가해야하는지 판단
def update_or_append_a_rule(NSG_Rules, private_IP, dst_port, src_ip, protocol): #TODO: 정보값 파라미터들 -> 리스트 OR 딕셔너리로 묶어서 넣던가, 클래스 만들어서 받기
    for rule in NSG_Rules:
        #Inbound Deny rule이 아니면 다음 rule으로 넘어감
        if rule["direction"] != "Inbound" or rule["access"] != "Deny" : 
            continue

        #프로토콜이 ALL 또는 위협 IP의 프로토콜과 같지 않으면 다음 rule으로 넘어감
        if rule["protocol"] != "*" or rule["protocol"] != protocol :
            continue 

        #dst_ip, dsp_port, src_ip 체크 메소드 결과를 확인 
        bool1, DST_IP = check_dst_ip(rule, private_IP) 
        bool2, DST_PORT = check_dst_port(rule, dst_port) 
        bool3, SRC_IP = check_src_ip(rule, src_ip)

        #셋 중 하나라도 값(True)이 있으면 rule을 수정
        if bool1 or bool2 or bool3:
            return 1, write_JSON(DST_IP, DST_PORT, SRC_IP, rule["priority"], rule["name"], rule["protocol"]) #TODO: 파라미터 더 넣을것 없나
        else:
            name = f"MDCAutomation_src_공격아이피_{private_IP}_ALL_ALL_deny_ 시간"
            return 0, write_JSON(DST_IP, DST_PORT, SRC_IP, search_unoccupied_priority(),name, "*") #TODO: 무슨 우선순위로 할건지? -> 제일 작은 미사용 번호가 BEST
    
    return -1, False #?이미 같은 룰이 있는데 보안 경고가 울린 경우는?? 이 경우도 고려해야할지?       

#*Destination IP Address 체크
def check_dst_ip(rule, private_IP):
    try:
        if rule["destinationAddressPrefix"] : #destination IP Address에 값이 있는 경우  
            if rule["destinationAddressPrefix"] == "*" : #범위가 all IP인 경우
                return False, rule["destinationAddressPrefix"]
            
            if rule["destinationAddressPrefix"] == private_IP : #private_IP를 포함하는 경우
                return False, rule["destinationAddressPrefix"]
            
            return rule["destinationAddressPrefixes"].append(private_IP) #기존 string ip를 리스트에 합쳐야할 경우  
    except KeyError:
        logging.warning('"destinationAddressPrefix" does not exist.')

    try:
        if rule["destinationAddressPrefixes"]:  #destination IP Address 리스트에 값이 있는 경우
            if private_IP in rule["destinationAddressPrefixes"] :  #범위에 private_IP를 포함하는 경우
                return False, rule["destinationAddressPrefixes"]
            
            return rule["destinationAddressPrefixes"].append(private_IP) #리스트에 ip를 추가해야할 경우
    except KeyError:
        logging.warning('"destinationAddressPrefixes" does not exist.') #문자열, 리스트 둘 중 하나는 반드시 값이 있음. 

#*Destination Port 체크
def check_dst_port(rule, dst_port):
    try:
        if rule["destinationPortRange"] : #destination Port에 값이 있는 경우
            if rule["destinationPortRange"] == "*" : #all port인 경우
                return False, rule["destinationPortRange"]

            if not port_check(rule["destinationPortRange"], dst_port): #dst_port를 포함하는지 확인
                return False, rule["destinationPortRange"]
            
            return rule["destinationPortRanges"].append(dst_port) #기존 port를 리스트에 합쳐야할 경우
    except KeyError:
        logging.warning('"destinationPortRange" does not exist.')

    try:
        if rule["destinationPortRanges"]:  #destination Port 리스트에 값이 있는 경우
            for port_string in rule["destinationPortRanges"]: #여러 범위들 중 dst_port가 포함되어 있는지 확인
                if not port_check((port_string), dst_port):
                    return False, rule["destinationPortRanges"]
                
            return rule["destinationPortRanges"].append(dst_port) #리스트에 port를 추가해야할 경우
    except KeyError:
        logging.warning('"destinationPortRanges" does not exist.')
    #?근데 만약.. [80,88] 범위에 89 포트가 추가되야 할 때는?그건 나중에 생각해..

#*Source IP Address 체크
def check_src_ip(rule, src_ip):
    try: #규칙에서 찾는 인덱스가 없을 수 있음
        if rule["sourceAddressPrefix"] : #source IP Address에 값이 있는 경우
            if rule["destinationAddressPrefix"] == "*" : #범위가 all IP인 경우
                return False, rule["destinationAddressPrefix"]
            
            if rule["destinationAddressPrefix"] == src_ip : #src_IP를 포함하는 경우
                return False, rule["destinationAddressPrefix"]
            
            return rule["sourceAddressPrefixes"].append(src_ip) #기존 string ip를 리스트에 합쳐야할 경우   
    except KeyError:
        logging.warning('"sourceAddressPrefix" does not exist.')
    
    try:
        if rule["sourceAddressPrefixes"]: #source IP Address 리스트에 값이 있는 경우
            if src_ip in rule["destinationAddressPrefixes"] : #범위에 src_IP를 포함하는 경우
                return False, rule["destinationAddressPrefixes"]
            
            return rule["destinationAddressPrefixes"].append(src_ip) #리스트에 ip를 추가해야할 경우
    except KeyError:
        logging.warning('"sourceAddressPrefixes" does not exist.')

#TODO:기존 NSG 규칙 수정
def update_NSG_Rule(token):
    URL = "추가"
    pass

#TODO:새로운 NSG 규칙 생성
def create_NSG_Rule(token):
    URL = "추가해야함"
    pass

#*포트 범위 인지, 포트 번호만 있는지 확인 후 포트가 포함됐는지까지 확인
def port_check(port_string, port):
    if port_string in '-': #포트 범위
        return port_in_range(port_string, port)
    elif port_string == port: #포트 번호
        return False

#*포트 범위 쪼개고, 정수로 변환
def port_in_range(port_range, port):
    #문자열 split
    port_list = port_range.split('-')

    #정수로 변환 -> 범위 내에 포트가 포함됐는지 확인
    if port in range(int(port_list[0]), int(port_list[1])):
        return False
    else:
        return True

#TODO: 미사용 우선순위 번호 찾기
def search_unoccupied_priority():
    pass

#TODO: POST할 json 작성
def write_JSON(dst_ip, dst_port, src_ip, priority, name, protocol):
    pass