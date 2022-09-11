import requests
import threading
from urllib import parse
import os
def WriteText(file):
        urls=[]
        file =open(file)#将列表中内容追加到字典里，若空则break
        while True:
            text =file.readline()
            textcl=text.strip('\n')
            if not text:
                break
            urls.append(textcl)
        file.close()
        return urls

def xss(urldata):
        max_connections = 20  # 定义最大线程数
        pool_sema = threading.BoundedSemaphore(max_connections) # 或使用Semaphore方法
        pool_sema.acquire()
        proxy={"http":"127.0.0.1:8080","https":"127.0.0.1:8080"}
        header={"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"}
        xssfilter=["<h1>sb</h1>","sb\"7"]
        result = parse.urlparse(urldata)
        query_dict = parse.parse_qs(result.query).values()
        print(urldata)
        for i in query_dict:
            paramater=''.join(str(n) for n in i).strip()
            url=urldata.replace(paramater,paramater+"sb\"7<h1>sb</h1>")
            try:
                res=requests.get(url=url,headers=header)
            except:
                continue
            header=res.headers.get("Content-Type")
            
            if header==None:
                continue
            if ("text/html" in header):
                if any(e in res.text for e in xssfilter):
                    print("\033[1;31m"+urldata+"\033[0m")
                    file = open("xss_vlu.txt", "a")
                    file.write(urldata+'\n')
            else:
                continue
        pool_sema.release()

def doxsstxt(file1,file2):
        filter=[".gif?",".css?",".js?",".jpg?",".png?"]
        f = open(file1,encoding='utf-8')

        while True:
            line = f.readline()
            try:
                if line:
                    if (not any(e in line for e in filter)):
                        urls=open(file2).read()
                        with open(file2, 'a') as xssfile:
                            if line not in urls:
                                xssfile.write(line)
                            else:
                                continue
                else:
                    break
            except :
                continue
        f.close()

for domain in open('test.txt'):
    print(domain)
    output = os.popen('/Users/chenguang/go/bin/gau --proxy http://127.0.0.1:7890 --blacklist svg,png,jpg,gif,css,js,png,swf '+domain.strip()+' | grep \? | grep = > ~/xss.txt')
    print(output.read())
    with open("xss.txt", 'r+') as file:
        file.truncate(0)
    doxsstxt("/Users/chenguang/xss.txt","xss.txt")
    urls1=WriteText('xss.txt')
    n=1000     #将列表每1000个组成一个小列表
    x=0
    for i in range(0, len(urls1),n):
        multithread=[]
        url_list=urls1[i:i + n]
        for url in url_list:
            one_thread = threading.Thread(target=xss, args=(url,))    #将该url作为一个线程加入多线程的列表
            multithread.append(one_thread)
        for j in multithread:                       #执行多线程
            j.start()
        for j in multithread:                       #为了防止子线程没结束主线程就先结束了
            j.join()
