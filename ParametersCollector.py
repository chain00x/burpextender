# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from java.util import ArrayList;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JButton;
from javax.swing import JTabbedPane;
from javax.swing import JTextField;
from javax.swing import JTable;
from javax.swing import JToggleButton
from javax.swing.table import AbstractTableModel
from threading import Lock
import re
import os
import json
import sys  
reload(sys)  
sys.setdefaultencoding('utf8')



def getJsonKey(json_data):
    key_list=[]
    #递归获取字典中所有key
    for key in json_data.keys():
        if type(json_data[key])==type({}):
            getJsonKey(json_data[key])
        key_list.append(key)
    return key_list
print("""Para""")
paras=[]
# 定义保存域名，参数，URL 的类
class LogEntry:
    def __init__(self, host, paras):
        self._host = host
        self._count = len(paras)
        self._paras = paras

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._parasViewer.setText(logEntry._paras)
        # self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    


class BurpExtender(IBurpExtender, IHttpListener, IHttpRequestResponse, ITab, IMessageEditorController, AbstractTableModel):


    def registerExtenderCallbacks(self,callbacks):
        

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName('ParasCollector')
        self._log = ArrayList()
        self._lock = Lock()
        # 主窗口
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        logTable = Table(self)
        Pane3=JSplitPane(JSplitPane.VERTICAL_SPLIT)
        Pane4=JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        Pane5=JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.starbutton=JToggleButton("ParametersCoollector is off",actionPerformed=self.startOrStop)
        self.searchinput=JTextField('',120)
        self.searchbutton=JToggleButton('Not Filter',actionPerformed=self.search)
        Pane5.add(self.searchbutton)
        Pane5.add(self.starbutton)
        scrollPane = JScrollPane(logTable)
        Pane4.add(self.searchinput)
        Pane4.add(Pane5)
        Pane3.add(Pane4)
        Pane3.add(scrollPane)
        
        self._splitpane.setLeftComponent(Pane3)
        
        # 详情
        Pane2=JSplitPane(JSplitPane.VERTICAL_SPLIT)
        

        clearbutton=JButton('Clear',actionPerformed=self.clearList)
        Pane2.add(clearbutton)
        
        tabs = JTabbedPane()
        self._parasViewer = callbacks.createTextEditor()
        
        tabs.addTab("Paras",self._parasViewer.getComponent())
        Pane2.add(tabs)
        self._splitpane.setRightComponent(Pane2)

        self.intercept = 0

        # 定义 UI 组件
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        # 将 UI 组件添加到 BURP 的 UI
        callbacks.addSuiteTab(self)


        # 注册功能
        callbacks.registerHttpListener(self)

        return

    def clearList(self,event):
        oldrow = self._log.size()
        # self._lock.acquire()
        with open('/Users/chenguang/PycharmProjects/pythonProject/allparas.json','w') as f:
            f.write('')
        self.fireTableRowsDeleted(0, oldrow-1)
        self._log.clear()
        # self._lock.release()
    def startOrStop(self, event):
        if self.starbutton.getText() == "ParametersCoollector is off":
            self.starbutton.setText("ParametersCoollector is on")
            self.starbutton.setSelected(True)
            self.intercept = 1
        else:
            self.starbutton.setText("ParametersCoollector is off")
            self.starbutton.setSelected(False)
            self.intercept = 0

    def search(self,event):
        if self.searchbutton.getText() == "Not Filter":
            self.searchbutton.setText("Filter")
            self.searchbutton.setSelected(True)
            try:
                with open('allparas.json','r') as f:
                    data=f.read()
                input=self.searchinput.text
                oldrow = self._log.size()
                jsondata=json.loads(data)
                for i in range(0,oldrow):
                    host=self.getValueAt(i,0)
                    if input not in self.getValueAt(i,0):
                        jsondata.pop(host)
                        with open("allparas.json","w+") as j:
                            json.dump(jsondata, j, ensure_ascii=False)
                self.fireTableDataChanged()
            except:
                self.fireTableDataChanged()
        else:
            self.searchbutton.setText("Not Filter")
            self.searchbutton.setSelected(False)

    def getTabCaption(self):
        return "ParasCollector"
    
    def getUiComponent(self):
        return self._splitpane
        

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.intercept == 1:
            if toolFlag == 4:
                # 读 json 文件取得数据
                self._lock.acquire() # 加锁，反应会慢一点
                try:
                    with open("allparas.json","r") as f:
                        allparas = json.loads(f.read())
                except Exception as ex:
                    allparas = {}

                host = messageInfo.getHttpService().getHost().encode('utf-8')
                
                    
                    
                paras = allparas.get(host)
                if paras == None:
                    paras = []
                # print(type(paras))
                if messageIsRequest: # 如果是一个请求
                    
                        
                        request = messageInfo.getRequest() # 获得请求信息
                        
                        analyzedRequest = self._helpers.analyzeRequest(request)
                        paras1 = analyzedRequest.getParameters()
                        Request_hreaders=analyzedRequest.getHeaders()
                        request_bodys = request[analyzedRequest.getBodyOffset():].tostring()
                        if '":' in request_bodys:
                            try:
                                    jsonbody=json.loads(body)
                            except Exception:
                                jsonbody=''
                            if type(jsonbody)==dict:
                                Parameters=getJsonKey(jsonbody)
                                for para in Parameters:
                                    if para not in paras: # 去重
                                        paras.append(str(para))
                        
                        # Request_hreaders1=''.join(str(i) for i in Request_hreaders)
                        # print(Request_hreaders[0])
                        if '?' in Request_hreaders[0] or '=' in request_bodys:
                            for para in paras1:
                                temp = str(para.getName())
                                if temp not in paras and (temp in Request_hreaders[0] or temp in request_bodys): # 去重、去cookie参数
                                        paras.append(temp)
                        if paras !=[]:
                            paras.sort()
                            allparas[host] = paras
                        
                if not messageIsRequest: # 如果是个响应
                    
                        response = messageInfo.getResponse() # 获得响应信息
                        analyzedResponse = self._helpers.analyzeResponse(response)
                        resquest = messageInfo.getRequest()
                        analyzedRequest = self._helpers.analyzeResponse(resquest)
                        # request_header = analyzedRequest.getHeaders()
                        
                        if analyzedResponse.getInferredMimeType() == "JSON":
                            body = response[analyzedResponse.getBodyOffset():].tostring() # 获取返回包
                            try:
                                jsonbody=json.loads(body)
                            except Exception:
                                jsonbody=''
                            if type(jsonbody)==dict:
                                
                                Parameters=getJsonKey(jsonbody)
                                for para in Parameters:
                                    if para not in paras: # 去重
                                        paras.append(str(para))
                        if paras !=[]:
                            paras.sort()
                            allparas[host] = paras
                if allparas != {} and self.searchinput.text in host:
                    with open("allparas.json","w+") as f:
                        json.dump(allparas, f, ensure_ascii=False)
                
                row = self._log.size()
                self._log.clear()
                for host in allparas.keys():
                    self._log.add(LogEntry(host, '\n'.join(allparas.get(host))))
                    self.fireTableRowsInserted(row, row)
                self._lock.release()

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "HOST"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._host
        return ""
