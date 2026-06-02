# Event_category = {
#     "UserID": 'integer'
#     "EventID": "nvarchar(10)",
#     "Computer": "nvarchar(20)",
#     "EventRecordID": "nvarchar(255)",
#     "TimeCreated": "nvarchar(255)",
#     "RuleName": "text",
#     "UtcTime": "nvarchar(255)",
#     "ProcessGuid": "nvarchar(255)",
#     "ProcessId": "nvarchar(255)",
#     "Image": "nvarchar(255)",
#     "FileVersion": "nvarchar(255)",
#     "Description": "nvarchar(255)",
#     "Product": "nvarchar(255)",
#     "Company": "nvarchar(255)",
#     "OriginalFileName": "nvarchar(255)",
#     "CommandLine": 'text',
#     "CurrentDirectory": "nvarchar(255)",
#     "User": "nvarchar(255)",
#     "LogonGuid": "nvarchar(255)",
#     "LogonId": "nvarchar(255)",
#     "TerminalSessionId": "nvarchar(255)",
#     "IntegrityLevel": "nvarchar(255)",
#     "Hashes": "text",
#     "ParentProcessGuid": "nvarchar(255)",
#     "ParentProcessId": "nvarchar(255)",
#     "ParentImage": "nvarchar(255)",
#     "ParentCommandLine": 'text',
#     "ParentUser": "nvarchar(255)",
# }

import asyncio
from enum import Enum
import threading

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    Depends,
    Query,
    Response,
    WebSocketException,
    status,
)
from fastapi.responses import HTMLResponse
from httpx import stream
from numpy import integer
from pydantic import BaseModel
from bs4 import BeautifulSoup
import logging
import pandas as pd
from sigma.rule import SigmaLogSource, SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon.sysmon import sysmon_pipeline
import yaml
from typing import Annotated
import random
import sqlite3
from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.backends.dictquery.dictquery import DictQueryBackend
import json
from sigma.processing.pipeline import ProcessingPipeline
from sigma.conversion.base import Backend
from sigma.correlations import SigmaCorrelationRule
from elasticsearch import Elasticsearch
import dictquery
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import queue
import os

Event_category = {
    "EventID": "nvarchar(10)",
    "Computer": "nvarchar(20)",
    "EventRecordID": "nvarchar(255)",
    "TimeCreated": "nvarchar(255)",
    "RuleName": "text",
    "UtcTime": "nvarchar(255)",
    "ProcessGuid": "nvarchar(255)",
    "ProcessId": "nvarchar(255)",
    "Image": "nvarchar(255)",
    "FileVersion": "nvarchar(255)",
    "Description": "nvarchar(255)",
    "Product": "nvarchar(255)",
    "Company": "nvarchar(255)",
    "OriginalFileName": "nvarchar(255)",
    "CommandLine": "text",
    "CurrentDirectory": "nvarchar(255)",
    "User": "nvarchar(255)",
    "LogonGuid": "nvarchar(255)",
    "LogonId": "nvarchar(255)",
    "TerminalSessionId": "nvarchar(255)",
    "IntegrityLevel": "nvarchar(255)",
    "Hashes": "text",
    "ParentProcessGuid": "nvarchar(255)",
    "ParentProcessId": "nvarchar(255)",
    "ParentImage": "nvarchar(255)",
    "ParentCommandLine": "text",
    "ParentUser": "nvarchar(255)",
}


class agentModel:
    id: int
    username: str
    token: str

    def __init__(self, id, username, token):
        self.id = id
        self.username = username
        self.token = token


class eventModel(BaseModel):
    event: str


class userModel(BaseModel):
    username: str
    password: str


class responseModel(BaseModel):
    message: str

    
class serverityEnum(Enum):
    high = 'high'
    medium = 'medium'
    low = 'low'
    informational = 'infoamtional'

class event_table:
    class attribute:
        userid = 'userid'
        rowid = 'rowid'
        TimeCreated = 'TimeCreated'
        log = 'log'
    def __init__(self, log: str | dict, TimeCreated: str, rowid:int | None = None, userid: int | None = None) -> None:
        self.log = log
        self.rowid = rowid
        self.userid = userid
        self.TimeCreated = TimeCreated
        pass
    
    def tojson(self, includerowid: bool) -> str:
        return json.dumps(self.todict(includerowid, rawstringencode=False))

    def getuseridjson(self) -> str:
        dict = {
            self.attribute.userid : self.userid
        }
        return json.dumps(dict)
    
    def getuserid(self) -> int|None:
        return self.userid
    
    def getTimeCreated(self) -> str:
        return self.TimeCreated
    def getTimeCreatedjson(self) -> str:
        return json.dumps({self.attribute.TimeCreated: self.TimeCreated})


    def getlogjson(self) -> str:
        if isinstance(self.log, str):
            return self.log
        res = json.dumps(self.getlogdict())
        return res
    
    def getlogdictundecode(self) -> dict[str,str]:
        if isinstance(self.log, str):
            event_dict: dict[str, str] = json.loads(self.log)
            res:dict[str, str] = {}
            for key, value in event_dict.items():
                # if isinstance(value, str):
                #     value = value.encode('unicode_escape').decode()
                res.update({(key, value)})
        else:
            res = self.log
        if isinstance(res, dict):
            for key, value in res.items():
                if isinstance(value, str):
                    res[key] = value
        return res

    def getlogdict(self) -> dict[str, str]:
        if isinstance(self.log, str):
            event_dict: dict[str, str] = json.loads(self.log)
            res:dict[str, str] = {}
            for key, value in event_dict.items():
                # if isinstance(value, str):
                #     value = value.encode('unicode_escape').decode()
                res.update({(key, value)})
        else:
            res = self.log
        if isinstance(res, dict):
            for key, value in res.items():
                if isinstance(value, str):
                    res[key] = value.encode('unicode_escape').decode()
        return res

    def todict(self, includerowid: bool, rawstringencode: bool) -> dict[str, str | int | None]:
        res:dict[str, str | int | None]
        if includerowid:
            res  = {
            self.attribute.rowid: self.rowid,
            self.attribute.userid: self.userid,
        }
        else:
            res = {
            self.attribute.userid: self.userid,
        }
        res.update({self.attribute.TimeCreated: self.getTimeCreated()})
        if rawstringencode:
            res.update(self.getlogdict())
        else:
            res.update(self.getlogdictundecode())
        return res
    def __str__(self) -> str:
        return self.tojson(True)


class ProcessRule:
    logged_events = []


    def __init__(self, Host: str, Port: int, agent: agentModel):
        self.Host = Host
        self.Port = Port
        self.agent = agent

    def CheckEvent(self, event: BeautifulSoup):
        event_dict = {}

        def get_text(tag: str):
            foundtag = event.find(tag)
            if foundtag is not None:
                value = foundtag.getText()
                if value is not None:
                    return value
            return None

        def get_attribute(tag: str, attr: str):
            foundtag = event.find(tag)
            if foundtag is not None:
                value = foundtag.get(attr)
                if value is not None:
                    return value
            return None
        eventid = get_text("EventID")
        assert eventid is not None
        event_dict["EventID"] = int(eventid)
        event_dict["Computer"] = get_text("Computer")
        event_dict["EventRecordID"] = get_text("EventRecordID")
        event_dict["TimeCreated"] = get_attribute("TimeCreated", "SystemTime")
        eventdata = event.find("EventData")
        if eventdata is not None:
            for data in eventdata.find_all("Data"):
                name = data.get("Name")
                event_dict[name] = data.getText()
        event_obj = event_table(log=event_dict, userid=self.agent.id, TimeCreated=str(event_dict['TimeCreated']))
        sqlite_insert_event(self.agent.id, event_obj)
        self.logged_events.append(event_dict)
    


    def PrintDataFrame(self):
        dataframe = pd.DataFrame(self.logged_events)
        dataframe["EventID"] = pd.to_numeric(dataframe["EventID"], errors="coerce")
        dataframe["TimeCreated"] = pd.to_datetime(
            dataframe["TimeCreated"], errors="coerce", utc=True
        )

        dataframe = dataframe.sort_values("TimeCreated").set_index("TimeCreated")
        logger.debug(dataframe)

def parse_beautifulsoup(event: eventModel) -> BeautifulSoup:
    soup = BeautifulSoup(event.event, features="xml")
    return soup

def parse_rule_json(Title: str, Description: str, Severity: str, Query: list[str]) -> dict:
    rule = {
        'Title' : Title,
        'Description': Description,
        'Severity': serverityEnum[Severity].value,
        'Query': Query
    }
    return rule


def turntorawstring(string: str) -> str:
    return string.encode('unicode_escape').decode()

def sqlite_get_user(user: dict[str, str]) -> dict[str, str] | None:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    sql = f"Select rowid, * from {usertable} where username = ?"
    values = (user["username"],)
    cursor.execute(sql, values)
    user_res = cursor.fetchone()
    cursor.close()
    if user_res is None:
        return None
    return {
        "id": user_res[0],
        "username": user_res[1].__str__(),
        "password": user_res[2].__str__(),
    }

def sqlite_get_user_list() -> list[dict[str, str]] | None:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    sql = f"Select rowid, * from {usertable}"
    cursor.execute(sql)
    user_res = cursor.fetchall()
    cursor.close()
    conn.close()
    if user_res is None:
        return None
    user_list = []
    for user in user_res:
        to_append_user = {"id": user[0], "username": user[1].__str__()}
        user_list.append(to_append_user)
    return user_list


def sqlite_create_user(user: dict[str, str]):
    cursor = sqlite.cursor()
    username = user["username"]
    password = user["password"]
    sql = f"insert into {usertable}(username, password) values (?, ?)"
    value = (username, password)
    cursor.execute(sql, value)
    sqlite.commit()
    cursor.close()
    logger.debug("user inserted")


def sqlite_auth_user(user: dict[str, str]) -> bool:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    sql = f"Select * from {usertable} where username = ? and password = ?"
    values = (
        user["username"],
        user["password"],
    )
    cursor.execute(sql, values)
    user_res = cursor.fetchone()
    cursor.close()
    if user_res is None:
        return False
    return True

def sqlite_insert_event(userid: int, event: event_table):
    cursor = sqlite.cursor()
    Query = f"insert into {eventtable}(userid, TimeCreated, log) values (?, ?, ?)"    
    values = (event.getuserid(), event.getTimeCreated(), event.getlogjson())
    cursor.execute(Query, values)
    cursor.close()
    sqlite.commit()
    logger.debug("event inserted")
    pass


def sqlite_get_user_event(id:int) -> list[dict[str, str | int| None]] | None:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    query = f"Select rowid, * from {eventtable} where userid = {id} order by TimeCreated desc"
    cursor.execute(query)
    event_res = cursor.fetchall()
    cursor.close()
    if event_res is None:
        return None
    list_dict: list[dict[str, str| int| None]] = []
    for event in event_res:
        rowid = event[0]
        userid = event[1]
        TimeCreated = event[2]
        log = event[3]
        eventobj = event_table(rowid=rowid, userid=userid, log=log, TimeCreated=TimeCreated)
        list_dict.append(eventobj.todict(includerowid=True, rawstringencode=False))
    return list_dict


def sqlite_get_detection_event(id: int) ->  list[dict[str, int | str]] | None:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    list_dict = []
    query = f'Select rowid, * from {eventtable} where userid = {id} order by TimeCreated Desc limit 5'
    cursor.execute(query)
    event_res = cursor.fetchall()
    cursor.close()
    if event_res is None:
        return None
    for rule in rules:           
        for event in event_res:
            rowid = event[0]
            userid = event[1]
            TimeCreated = event[2]
            log = event[3]
            eventobj = event_table(log=log, rowid=TimeCreated, userid=userid, TimeCreated=TimeCreated)
            try:

                
                event_dict = eventobj.getlogdict()
                # logger.debug(event_dict)
                # logger.debug(r'EventID==1 AND (Image LIKE "*\\Code.exe")')
                # if event_dict.get('Image') is not None:
                    #event_dict['Image'] = event_dict['Image'].encode('unicode_escape').decode()
                    # logger.debug(event_dict['Image'])
                # test_dict ={
                #     'EventID': 1,
                #     'Image' : r'fdsfdsa\\Code.exe'
                # }
                detection_query = dictquery.compile(rule['Query'][0].encode('unicode_escape').decode()) 
                #detection_query = dictquery.compile(r'EventID==3 AND (Image LIKE "*\\Code.exe")') 
                # if detection_query.match(test_dict):
                #     logger.debug('True')
                # else:
                #     logger.debug(detection_query.evaluate(event_dict))
                if detection_query.match(event_dict):
                    rowid = event[0]
                    userid = event[1]
                    event_dict = {
                        "UserID": userid,
                        'Title' : rule['Title'],
                        'Description': rule['Description'],
                        'Severity': rule['Severity'],
                        'EventRowID': rowid
                        }
                    list_dict.append(event_dict)
                # else:
                #     if event_dict.get('Image') is not None:
                #         logger.debug(event_dict['EventID'])
                #         logger.debug(event_dict['Image'].encode('unicode_escape').decode())
            except Exception as e:
                logger.debug(eventobj)
                logger.debug(rule)
                logger.debug('Detection error: ' + e.__str__())
    return list_dict


def parse_user(user: userModel) -> dict[str, str]:
    return {"username": user.username, "password": user.password}

app = FastAPI()


@app.get("/")
async def root():
    return HTMLResponse(content="hello", status_code=200)


@app.get("/dashboard")
async def get_dashboard():
    dashboard = open("Dashboard.html", mode="r").read()
    return HTMLResponse(dashboard)


@app.get("/dashboard/getuserlist")
async def get_user_list():
    return responseModel(message=f"{json.dumps(sqlite_get_user_list())}")

@app.get('/dashboard/getdetectionalert')
async def get_detection_alert(id: int):
    return responseModel(message=f"{json.dumps(sqlite_get_detection_event(id))}")

@app.get("/dashboard/getuserevent")
async def get_user_event(id: int):
    return responseModel(message=f"{json.dumps(sqlite_get_user_event(id))}")


@app.post("/dashboard/createuser")
async def create_user(user: userModel, response: Response):
    user_dict = parse_user(user)
    try:
        if sqlite_get_user(user_dict) is not None:
            response.status_code = status.HTTP_403_FORBIDDEN
            return responseModel(message="User already exist")
        q.put((sqlite_create_user, user_dict))
        response.status_code = status.HTTP_200_OK
        return responseModel(message="User successfully created")
    except Exception as e:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return responseModel(message=f"{e}")


@app.post("/auth")
async def get_user(user: userModel, response: Response):
    user_dict = parse_user(user)
    if sqlite_auth_user(user_dict):
        while True:
            characters = "abcdefghijklmnopqrstuvwxyz0123456789"
            token = "".join(random.choice(characters) for _ in range(8))
            if token not in generated_token:
                break
        founduser = sqlite_get_user(user_dict)
        assert founduser is not None
        agent = agentModel(founduser["id"], founduser["username"], token)
        generated_token.append(agent)
        response.status_code = status.HTTP_200_OK
        return responseModel(message=token)
    response.status_code = status.HTTP_403_FORBIDDEN
    return responseModel(message="credential invalid")
        


def get_token(socket: WebSocket, token: Annotated[str | None, Query()] = None):
    if token is None:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    found: bool = False
    for gen_token in generated_token:
        if token == gen_token.token:
            found = True
            break
    if found is False:
        logger.debug('wrong token')
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    return token


def get_generated_token_from_token(token: str) -> agentModel | None:
    for iter_token in generated_token:
        if token == iter_token.token:
            return iter_token
    return None

def queueworker():
    while True:
        (func, data) = q.get()
        func(data)
        q.task_done()

@app.websocket("/ws")
async def websocket_endpoint(
    socket: WebSocket, token: Annotated[str, Depends(get_token)]
):
    await socket.accept()
    Host = socket.client
    assert Host is not None
    agent = get_generated_token_from_token(token)
    assert agent is not None
    processmonitor = ProcessRule(Host.host, Host.port, agent)
    MonitorList.append(processmonitor)
    def process_event(data) -> None:
        data = eventModel(**data)
        event = parse_beautifulsoup(data)
        processmonitor.CheckEvent(event=event)
    try:
        while True:
            data = await socket.receive_json()
            q.put((process_event, data))
            await socket.send_text('received')
    except WebSocketDisconnect:
        logger.debug(f"{agent.username} has left")
    except Exception as e:
        logger.debug(f"error: {e}")
    finally:
        q.join()
        generated_token.remove(agent)
        MonitorList.remove(processmonitor)





print("program running")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s:\n\t%(message)s"
)
ThreadLock = Lock()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
rules: list[dict] = []
MonitorList: list[ProcessRule] = []
#backend: DictQueryBackend
pipelines = sysmon_pipeline()
backend = DictQueryBackend(pipelines)
folderpath = 'pipeline'
for dir in os.scandir(folderpath):
    for e in os.scandir(dir.path):
        if e.is_file():
            with open(e.path, 'r', encoding= "utf-8") as f:
                datas = yaml.load_all(f, Loader=yaml.FullLoader)
                index = 0
                rule_list = []
                rule_yaml: SigmaCollection
                try:
                    for data in datas:
                        
                            yaml_string = yaml.dump(data)
                            rule: SigmaRule | SigmaCorrelationRule
                            try:
                                rule = SigmaRule.from_yaml(yaml_string)
                            except Exception as e:
                                raise Exception(e)
                                rule = SigmaCorrelationRule.from_yaml(yaml_string)
                            rule_list.append(rule)
                            rule_yaml = SigmaCollection(init_rules=rule_list)
                            query = backend.convert(rule_yaml) #type: list[str]
                            rules.append(parse_rule_json(Title=data['title'], Description=data['description'], Severity=data['level'], Query=query))
                except Exception as e:
                    logger.debug('file name: ' + f.name)
                    logger.debug('Read rule exception: ' + e.__str__())
UserDB = "UserDB"
EventDB = 'EventDB'
usertable = "user"
eventtable = "events"
cursor: sqlite3.Cursor
sqlite: sqlite3.Connection
sqlite = sqlite3.connect(f"{UserDB}.db", check_same_thread=False)
generated_token: list[agentModel] = []
cursor = sqlite.cursor()
cursor.execute(
    f"CREATE TABLE IF NOT EXISTS {usertable} (username VARCHAR(255), password VARCHAR(255))"
)
cursor.execute(f"CREATE TABLE IF NOT EXISTS {eventtable} (userid integer, TimeCreated text,log text)")
cursor.close()
q = queue.Queue()
threading.Thread(target= queueworker, daemon=True).start()
