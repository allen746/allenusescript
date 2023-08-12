
import threading
import requests
import sqlite3
import time

DBFileName = ''
TableName = ''
ThreadCount = 20

# TODO 1、模板
# 自定义的线程，多个线程执行，还可以获得结果
class EXPScanThread(threading.Thread):
    def __init__(self,func,args,name="",):
        threading.Thread.__init__(self)
        self.func = func
        self.args = args
        self.name = name
        self.result = None

    def run(self):
        print("thread:{} :start scan CVE: {},xuhao:{}".format(self.args[1],self.args[0],self.args[2]))
        self.result = self.func(self.args[0],)
        print("thread:{} :stop scan CVE: {}".format(self.args[1],self.args[0]))
    def get_result(self):
        threading.Thread.join(self)
        try:
            return self.result
        except Exception:
            return "Error"


# TODO 2、（1）样例1
# 检查每一个CVE是否有poc
def check_POC_every_CVE(CVEName=""):
    #apiKey = ""
    #url = "https://exploits.shodan.io/api/search?query=" + CVEName + "&key=" + apiKey
    url = "https://exploits.shodan.io/?q=" + CVEName
    try:
        response = requests.request("GET",url=url,verify=False,timeout=30)
        #total = json.loads(response.text)
    except Exception as e:
        print("Error,{}".format(CVEName))
        print(e)
        return "Error"
    if "Total Results" not in response.text:
        return "False"
    else:
        return "True"

# TODO 2、（1）样例2
# 更新CVEKB数据库中的hasPOC字段
def update_hasPOC(key = "Empty"):
    conn = sqlite3.connect(DBFileName)
    con = conn.cursor()
    if key == "All":
        sql = "select distinct(CVEName) from {}".format(TableName)
    elif key == "Empty":
        sql = "select distinct(CVEName) from {} where (hasPOC IS NULL) OR (hasPOC == '')".format(TableName)
    elif key == "Error":
        sql = "select distinct(CVEName) from {} where (hasPOC == 'Error')".format(TableName)
    con.execute(sql)
    # 在使用fetchall()方法后,会取得一个由元组构成的列表,即为[(CVE-2023-35321,),..............]
    cveNameList = con.fetchall()
    i = 0
    count = 1
    print('[+]cve列表去重后的数量为{}..............................'.format(len(cveNameList)))
    time.sleep(10)
    while i < len(cveNameList):
        print("|=========={}============|".format(i))
        tmpCount = ThreadCount if (len(cveNameList) - i) >= ThreadCount else len(cveNameList) - i
        threads = []
        for j in range(1,tmpCount+1):
            # func,args,name
            '''
            对应：
            print("thread:{} :start scan CVE: {},xuhao:{}".format(self.args[1],self.args[0],self.args[2]))
            print("thread:{} :stop scan CVE: {}".format(self.args[1],self.args[0]))
            '''
            t = EXPScanThread(check_POC_every_CVE,(cveNameList[i+j][0],j,i+j,),str(j))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        j = 1
        for t in threads:
            hasPOC = t.get_result()
            print(hasPOC)
            update_sql = "UPDATE "+TableName+" set hasPOC = '" + hasPOC + "' WHERE cveName == '" + cveNameList[i+j][0] +"';"
            conn.execute(update_sql)
            print("[+] update:{}".format(update_sql))
            j += 1
        i=i+ThreadCount
        conn.commit()