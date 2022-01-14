import requests
import json
import getpass
import socket
from requests.models import CaseInsensitiveDict

class Portal_User:
  def __init__(self):
    self.token = ""
    self.studentcode = ""
    self.year_term = []
    self.session = requests.Session()

  def __str__(self):
    if(self.token == ""):
      return "Didn't Sign in SKU Portal"
    else:
      return "Student Code is {}".format(self.studentcode)

  def SendData(self, msg):
      server_ip = "IP"
      port = 9999

      client = socket.socket()

      client.connect((server_ip, port))
      print("Server Coneected")

      send_msg = msg.encode('utf-8')
      client.send(send_msg)
      print(msg)

      receive = client.recv(1024)
      print(b'receive : ' + receive)
      
      client.close()

  def LoginPortal(self):
    self.studentcode = input("Sudent Code : ")
    URL = 'https://sportal.skuniv.ac.kr/sportal/auth2/login.sku'
    payload = { 'username': self.studentcode,
                'password': getpass.getpass(),
                'grant_type': 'password',
                'userType': 'sku'         }

    r = self.session.post(URL, json=payload)
    res = json.loads(r.text)

    if(res['RTN_STATUS'] == 'S'): #Login Successed
      #print(res['USER_INFO'])
      print(res['RTN_MESSAGE'])
      print(res['USER_INFO']['DEPT_NM'])
      self.SendData(res['USER_INFO']['DEPT_NM'])
      self.token = res['access_token']
      return True

    else: #Login Failed
      print(res['RTN_MESSAGE'])
      return False

  def getGradePage(self):
    payload = {"path":"selectList",
                "SYS_ID":"AL",
                "MAP_ID":"education.usc.USC_09001_V.select",
                "parameter":{"ID":self.studentcode,"STU_NO":self.studentcode},
                "userID":self.studentcode,
                "programID":"USC_09001_V",
                "accessToken":self.token}

    # For BearerAuth
    # Refer : https://reqbin.com/req/python/5k564bhv/get-request-bearer-token-authorization-header-example
    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = "Bearer " + self.token 
    ##

    URL = "https://sportal.skuniv.ac.kr/sportal/common/selectList.sku"
    r = self.session.post(URL, json=payload, headers=headers)
    result = json.loads(r.text)
    if(result["RTN_STATUS"] == "S"):
      list = result["LIST"]
      for data in list:
        print(data)
        self.year_term += [(data["YEAR_TERM"][:4], data["YEAR_TERM"][4:])]
    else:
      print(result["RTN_MESSAGE"])
    
    print(self.year_term)

  def getGradeDetail(self, year, term):
    payload = {"path":"selectList",
                "SYS_ID":"AL",
                "MAP_ID":"education.usc.USC_09001_V.select_sub",
                "parameter":{"SCH_YEAR":year, "SCH_TERM":term,"ID":self.studentcode, "STU_NO":self.studentcode},
                "userID":self.studentcode,
                "programID":"USC_09001_V",
                "accessToken":self.token}
    # For BearerAuth
    # Refer : https://reqbin.com/req/python/5k564bhv/get-request-bearer-token-authorization-header-example
    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = "Bearer " + self.token 
    ##

    URL = "https://sportal.skuniv.ac.kr/sportal/common/selectList.sku"
    r = self.session.post(URL, json=payload, headers=headers)
    result = json.loads(r.text)
    if(result["RTN_STATUS"] == "S"):
      list = result["LIST"]
      for data in list:
        print(data)
    else:
      print(result["RTN_MESSAGE"])

  def getLibraryInfo(self):
    f = open("Test.txt", "w")
    # For BearerAuth
    # Refer : https://reqbin.com/req/python/5k564bhv/get-request-bearer-token-authorization-header-example
    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = "Bearer " + self.token 
    ##
    URL = "https://sportal.skuniv.ac.kr/api/facilities/library/areas?q={%22isAvailable%22:true}&p={%22items._id%22:%200,%20%22issuedItems._id%22:%200}"
    r = self.session.get(URL, headers=headers)
    result = json.loads(r.text)

    for data in result:
      f.write("{} ({}) : {}층\n".format(data['title'], data['description'], data['floor']))
      print("{} ({}) : {}층".format(data['title'], data['description'], data['floor']))

      for notice in data["notices"]:
        f.write(notice["message"]+"\n")
        print(notice["message"])

      f.write("isAvailable : {}, isOpen : {}\n".format(data["isAvailable"], data["isOpen"]))    
      print("isAvailable : {}, isOpen : {}".format(data["isAvailable"], data["isOpen"]))

      for seat in data["items"]:
        f.write("{}, {}, {}\n".format(seat["id"], seat["type"], seat["available"]))
        print(seat["id"], seat["type"], seat["available"])

      f.write("----------------------------------------------------------------------------------------------------\n")
    f.close

  

user = Portal_User()
if(user.LoginPortal()):
  user.getGradePage()
  for terms in user.year_term:
    print(terms[0], terms[1])
    user.getGradeDetail(year = terms[0], term = terms[1])
  # user.getLibraryInfo()
  print(user)
