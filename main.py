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

from contextlib import asynccontextmanager
from enum import Enum
from re import S
from tempfile import template
import threading
from turtle import title

from charset_normalizer import detect
from fastapi import (
    FastAPI,
    Request,
    WebSocket,
    WebSocketDisconnect,
    Depends,
    Query,
    Response,
    WebSocketException,
    status,
)
from fastapi.templating import Jinja2Templates
from jinja2 import Template
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from numpy import tile
from pydantic import BaseModel
from bs4 import BeautifulSoup
import logging
import pandas as pd
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon.sysmon import sysmon_pipeline
import yaml
from typing import Annotated
import random
import sqlite3
from sigma.backends.dictquery.dictquery import DictQueryBackend
import json
import dictquery
from threading import Lock
import queue
import os
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

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
    high = "high"
    medium = "medium"
    low = "low"
    informational = "infoamtional"


class event_table:
    class attribute:
        userid = "userid"
        rowid = "rowid"
        TimeCreated = "TimeCreated"
        log = "log"

    def __init__(
        self,
        log: str | dict,
        TimeCreated: str,
        rowid: int | None = None,
        userid: int | None = None,
    ) -> None:
        self.log = log
        self.rowid = rowid
        self.userid = userid
        self.TimeCreated = TimeCreated
        pass

    def tojson(self, includerowid: bool) -> str:
        return json.dumps(self.todict(includerowid, rawstringencode=False))

    def getuseridjson(self) -> str:
        dict = {self.attribute.userid: self.userid}
        return json.dumps(dict)

    def getuserid(self) -> int | None:
        return self.userid

    def getTimeCreated(self) -> str:
        return self.TimeCreated

    def getTimeCreatedjson(self) -> str:
        return json.dumps({self.attribute.TimeCreated: self.TimeCreated})

    def getlogjson(self) -> str:
        if isinstance(self.log, str):
            return self.log
        res = json.dumps(self.getlogdictundecode())
        return res

    def getlogdictundecode(self) -> dict[str, str]:
        if isinstance(self.log, str):
            event_dict: dict[str, str] = json.loads(self.log)
            res: dict[str, str] = {}
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
        res: dict[str, str] = {}
        if isinstance(self.log, str):
            event_dict: dict[str, str] = json.loads(self.log)
            for key, value in event_dict.items():
                if isinstance(value, str):
                    value = turntorawstring(value)
                res.update({key: value})
        else:
            res = self.log
            for key, value in res.items():
                if isinstance(value, str):
                    res[key] = turntorawstring(value)
        return res

    def todict(
        self, includerowid: bool, rawstringencode: bool
    ) -> dict[str, str | int | None]:
        res: dict[str, str | int | None]
        if includerowid:
            res = {
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


class detectiontable:
    # (userid integer, TimeCreated text,Title nvarchar(255), Description text, level nvarchar(255), tag nvarchar(255), eventrowid integer)
    class attribute:
        userid = "userid"
        TimeCreated = "TimeCreated"
        Title = "Title"
        Description = "Description"
        level = "level"
        tag = "tag"
        eventrowid = "eventrowid"

    def __init__(
        self,
        userid: int,
        TimeCreated: str,
        Title: str,
        Description: str,
        level: str,
        tag: str | list[str],
        eventrowref: int,
    ) -> None:
        self.userid = userid
        self.TimeCreated = TimeCreated
        self.Title = Title
        self.Description = Description
        self.level = level
        self.tag = tag
        self.eventrowref = eventrowref

    def getuserid(self) -> int:
        return self.userid

    def getTimeCreated(self) -> str:
        return self.TimeCreated

    def getTitle(self) -> str:
        return self.Title

    def getDescription(self) -> str:
        return self.Description

    def getlevel(self) -> str:
        return self.level

    def gettag(self) -> str:
        if isinstance(self.tag, str):
            return self.tag
        else:
            res = ""
            res += self.tag[0]
            for i in range(1, len(self.tag)):
                res += self.tag[i]
            return res

    def geteventrowref(self) -> int:
        return self.eventrowref

    def todict(self) -> dict[str, str | int]:
        return {
            self.attribute.userid: self.getuserid(),
            self.attribute.TimeCreated: self.getTimeCreated(),
            self.attribute.Title: self.getTitle(),
            self.attribute.Description: self.getDescription(),
            self.attribute.level: self.getlevel(),
            self.attribute.tag: self.gettag(),
            self.attribute.eventrowid: self.geteventrowref(),
        }


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
        event_obj = event_table(
            log=event_dict,
            userid=self.agent.id,
            TimeCreated=str(event_dict["TimeCreated"]),
        )
        eventrowid = sqlite_insert_event(self.agent.id, event_obj)
        for rule in rules:
            if checkwithrule(event_obj.getlogdict(), turntorawstring(rule["Query"][0])):
                userid = self.agent.id
                TimeCreated = str(event_dict["TimeCreated"])
                title = str(rule.get("Title"))
                Description = str(rule.get("Description"))
                level = str(rule.get("Severity"))
                tag = str(rule.get("Tag"))
                eventrowref = eventrowid
                assert eventrowref is not None
                detection = detectiontable(
                    userid=userid,
                    TimeCreated=TimeCreated,
                    Title=title,
                    Description=Description,
                    level=level,
                    eventrowref=eventrowref,
                    tag=tag,
                )
                sqlite_insert_detection(detection=detection)
                pass
        self.logged_events.append(event_dict)

    def PrintDataFrame(self):
        dataframe = pd.DataFrame(self.logged_events)
        dataframe["EventID"] = pd.to_numeric(dataframe["EventID"], errors="coerce")
        dataframe["TimeCreated"] = pd.to_datetime(
            dataframe["TimeCreated"], errors="coerce", utc=True
        )

        dataframe = dataframe.sort_values("TimeCreated").set_index("TimeCreated")
        logger.debug(dataframe)


def checkwithrule(event: dict[str, str], rule: str) -> bool:
    # if event.get("Image") is not None:
    #     e = event.get("Image")
    #     assert e is not None
    #     if e.endswith("powershell.exe"):
    #         logger.debug(event)
    #         logger.debug(rule)
    def turn_lower_case(event: dict[str, str]):
        res = {}
        for key, value in event.items():
            if isinstance(value, str):
                res.update({key.casefold(): value.casefold()})
            else:
                res.update({key.casefold(): value})
        return res

    lower_case_event = turn_lower_case(event)
    try:
        if dictquery.match(lower_case_event, rule.casefold()):
            return True
        # if (
        #     lower_case_event["CommandLine"] is not None
        #     and lower_case_event["Image"].find("powershell.exe") != -1
        #     and rule.find("-encodedcommand") != -1
        # ):
        #     logger.debug(lower_case_event)
        #     logger.debug("rule: " + rule)
    except Exception as e:
        logger.debug(e)
        # logger.debug(event)
        # logger.debug(rule)
    return False


def parse_beautifulsoup(event: eventModel) -> BeautifulSoup:
    soup = BeautifulSoup(event.event, features="xml")
    return soup


def parse_rule_json(
    Title: str, Description: str, Severity: str, tag: str | list[str], Query: list[str]
) -> dict:
    rule = {
        "Title": Title,
        "Description": Description,
        "Severity": serverityEnum[Severity].value,
        "Tag": tag,
        "Query": Query,
    }
    return rule


def turntorawstring(string: str) -> str:
    return string.encode("unicode_escape").decode()


def sqlite_get_user(user: dict[str, str]) -> dict[str, str] | None:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    sql = f"Select rowid, * from {usertable} where username = ?"
    values = (user["username"],)
    cursor.execute(sql, values)
    user_res = cursor.fetchone()
    cursor.close()
    conn.close()
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


def sqlite_insert_detection(detection: detectiontable):
    cursor = sqlite.cursor()
    Query = f"insert into {detectiontablename}(userid, TimeCreated, Title, Description, level, tag, eventrowid) values (?, ?, ?, ?, ? ,?, ?)"
    values = (
        detection.getuserid(),
        detection.getTimeCreated(),
        detection.getTitle(),
        detection.getDescription(),
        detection.getlevel(),
        detection.gettag(),
        detection.geteventrowref(),
    )
    cursor.execute(Query, values)
    sqlite.commit()
    logger.debug("Detection found")
    id = cursor.lastrowid
    cursor.close
    return id
    pass


def sqlite_insert_event(userid: int, event: event_table):
    cursor = sqlite.cursor()
    Query = f"insert into {eventtable}(userid, TimeCreated, log) values (?, ?, ?)"
    values = (event.getuserid(), event.getTimeCreated(), event.getlogjson())
    cursor.execute(Query, values)
    sqlite.commit()
    id = cursor.lastrowid
    cursor.close()
    return id

    pass


def sqlite_get_user_event(id: int) -> list[dict[str, str | int | None]] | None:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    query = f"Select rowid, * from {eventtable} where userid = {id} order by TimeCreated desc"
    cursor.execute(query)
    event_res = cursor.fetchall()
    cursor.close()
    if event_res is None:
        return None
    list_dict: list[dict[str, str | int | None]] = []
    for event in event_res:
        rowid = event[0]
        userid = event[1]
        TimeCreated = event[2]
        log = event[3]
        eventobj = event_table(
            rowid=rowid, userid=userid, log=log, TimeCreated=TimeCreated
        )
        list_dict.append(eventobj.todict(includerowid=True, rawstringencode=False))
    return list_dict


def sqlite_get_single_event(id: int) -> dict[str, str | int | None]:
    logger.debug(id)
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    query = f"Select rowid, * from {eventtable} where rowid = {id}"
    cursor.execute(query)
    event = cursor.fetchone()
    cursor.close()
    rowid = event[0]
    userid = event[1]
    TimeCreated = event[2]
    log = event[3]
    eventobj = event_table(rowid=rowid, userid=userid, log=log, TimeCreated=TimeCreated)
    return eventobj.todict(includerowid=True, rawstringencode=False)
    pass


def sqlite_get_detection_event(id: int) -> list[dict[str, int | str]] | None:
    conn = sqlite3.connect(f"{UserDB}.db")
    cursor = conn.cursor()
    list_detection = []
    query = f"Select rowid, * from {detectiontablename} where userid = {id} order by TimeCreated desc"
    cursor.execute(query)
    detection_res = cursor.fetchall()
    cursor.close()
    for detection in detection_res:
        detectionobj = detectiontable(
            userid=detection[1],
            TimeCreated=detection[2],
            Title=detection[3],
            Description=detection[4],
            level=detection[5],
            tag=detection[6],
            eventrowref=detection[7],
        )
        list_detection.append(detectionobj.todict())
    return list_detection
    # userid, TimeCreated, Title, Description, level, tag, eventrowid
    # for event in event_res:
    #     rowid = event[0]
    #     userid = event[1]
    #     TimeCreated = event[2]
    #     Title = event[3]
    #     Description = event[4]
    #     level = event[5]
    #     tag = event[6]
    #     eventrowid = event[7]
    #     event_dict = {
    #         "UserID": userid,
    #         'TimeCreated': TimeCreated,
    #         'Title' : Title,
    #         'Description': Description,
    #         'Severity': level,
    #         'EventRowID': eventrowid
    #         }
    # if event_res is None:
    #     return None
    # for rule in rules:
    #     for event in event_res:
    #         rowid = event[0]
    #         userid = event[1]
    #         TimeCreated = event[2]
    #         log = event[3]
    #         eventobj = event_table(log=log, rowid=TimeCreated, userid=userid, TimeCreated=TimeCreated)
    #         try:

    #             event_dict = eventobj.getlogdict()
    #             # logger.debug(event_dict)
    #             # logger.debug(r'EventID==1 AND (Image LIKE "*\\Code.exe")')
    #             # if event_dict.get('Image') is not None:
    #                 #event_dict['Image'] = event_dict['Image'].encode('unicode_escape').decode()
    #                 # logger.debug(event_dict['Image'])
    #             # test_dict ={
    #             #     'EventID': 1,
    #             #     'Image' : r'fdsfdsa\\Code.exe'
    #             # }
    #             detection_query = dictquery.compile(rule['Query'][0].encode('unicode_escape').decode())
    #             #detection_query = dictquery.compile(r'EventID==3 AND (Image LIKE "*\\Code.exe")')
    #             # if detection_query.match(test_dict):
    #             #     logger.debug('True')
    #             # else:
    #             #     logger.debug(detection_query.evaluate(event_dict))
    #             if detection_query.match(event_dict):
    #                 rowid = event[0]
    #                 userid = event[1]
    #                 event_dict = {
    #                     "UserID": userid,
    #                     'Title' : rule['Title'],
    #                     'Description': rule['Description'],
    #                     'Severity': rule['Severity'],
    #                     'EventRowID': rowid
    #                     }
    #                 list_dict.append(event_dict)
    #             # else:
    #             #     if event_dict.get('Image') is not None:
    #             #         logger.debug(event_dict['EventID'])
    #             #         logger.debug(event_dict['Image'].encode('unicode_escape').decode())
    #         except Exception as e:
    #             logger.debug(eventobj)
    #             logger.debug(rule)
    #             logger.debug('Detection error: ' + e.__str__())
    # return list_dict


def parse_user(user: userModel) -> dict[str, str]:
    return {"username": user.username, "password": user.password}


def get_token(socket: WebSocket, token: Annotated[str | None, Query()] = None):
    if token is None:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    found: bool = False
    for gen_token in generated_token:
        if token == gen_token.token:
            found = True
            break
    if found is False:
        logger.debug("wrong token")
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    return token


def get_generated_token_from_token(token: str) -> agentModel | None:
    for iter_token in generated_token:
        if token == iter_token.token:
            return iter_token
    return None


def queueworker():
    global program_start
    while program_start:
        (func, data) = q.get()
        func(data)
        q.task_done()


def scanfolder(path):
    for e in os.scandir(path):
        if e.is_dir():
            scanfolder(e.path)
        if e.is_file() and e.name.endswith((".yaml", "yml")):
            with open(e.path, "r", encoding="utf-8") as f:
                datas = yaml.load_all(f, Loader=yaml.FullLoader)
                rule_list = []
                rule_yaml: SigmaCollection
                try:
                    for data in datas:
                        yaml_string = yaml.dump(data)
                        rule: SigmaRule
                        try:
                            rule = SigmaRule.from_yaml(yaml_string)
                        except Exception as e:
                            raise Exception(e)
                            # rule = SigmaCorrelationRule.from_yaml(yaml_string)
                        rule_list.append(rule)
                        rule_yaml = SigmaCollection(rules=rule_list)
                        query = backend.convert(rule_yaml)  # type: list[str]
                        rules.append(
                            parse_rule_json(
                                Title=data["title"],
                                Description=data["description"],
                                Severity=data["level"],
                                tag=list(data["tags"]),
                                Query=query,
                            )
                        )
                except Exception as e:
                    logger.debug("file name: " + f.name)
                    logger.debug("Read rule exception: " + e.__str__())
                    raise e
    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    program_start = True
    yield
    program_start = False
    sqlite.close()


print("program running")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s:\n\t%(message)s"
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
rules: list[dict] = []
MonitorList: list[ProcessRule] = []
# backend: DictQueryBackend
pipelines = sysmon_pipeline()
backend = DictQueryBackend(pipelines)  # type: ignore
folderpath = "pipeline"
scanfolder(folderpath)
logger.debug(rules)
UserDB = "UserDB"
EventDB = "EventDB"
usertable = "user"
eventtable = "events"
detectiontablename = "detection"
cursor: sqlite3.Cursor
sqlite: sqlite3.Connection
sqlite = sqlite3.connect(f"{UserDB}.db", check_same_thread=False)
generated_token: list[agentModel] = []
program_start: bool = True
cursor = sqlite.cursor()
cursor.execute(
    f"CREATE TABLE IF NOT EXISTS {usertable} (username VARCHAR(255), password VARCHAR(255))"
)
event_table_attribute = event_table.attribute
cursor.execute(
    f"CREATE TABLE IF NOT EXISTS {eventtable} ({event_table_attribute.userid} integer, {event_table_attribute.TimeCreated} text, {event_table_attribute.log} text)"
)
detection_table_attr = detectiontable.attribute
cursor.execute(
    f"CREATE TABLE IF NOT EXISTS {detectiontablename} ({detection_table_attr.userid} integer, {detection_table_attr.TimeCreated} text,{detection_table_attr.Title} nvarchar(255), {detection_table_attr.Description} text, {detection_table_attr.level} nvarchar(255), {detection_table_attr.tag} nvarchar(255), {detection_table_attr.eventrowid} integer)"
)
cursor.execute("pragma journal_mode=wal")
cursor.close()
q = queue.Queue()
threading.Thread(target=queueworker, daemon=True).start()

origins = [
    # "http://localhost: 5173"
    "*"
]

app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="Template")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return HTMLResponse(content="hello", status_code=200)


# @app.get('/js/{file}')
# def get_js_file(file: str):
#     path = os.path.dirname(__file__)
#     path = os.path.join(path, 'js', file)
#     return FileResponse(path)
# with open(path, mode= 'r', newline='\r\n') as f:
#     return f.read()


# @app.get("/dashboard", response_class=HTMLResponse)
# def get_dashboard(request: Request):
#     # dashboard = open("Dashboard.html", mode="r").read()
#     # html_res = Template(dashboard)
#     # website = html_res.render()
#     return templates.TemplateResponse(request=request, name='Dashboard.html')


@app.get("/dashboard/getuserlist")
def get_user_list():
    return responseModel(message=f"{json.dumps(sqlite_get_user_list())}")


@app.get("/dashboard/getdetectionalert")
def get_detection_alert(id: int):
    return responseModel(message=f"{json.dumps(sqlite_get_detection_event(id))}")


@app.get("/dashboard/getuserevent")
def get_user_event(id: int):
    return responseModel(message=f"{json.dumps(sqlite_get_user_event(id))}")


@app.get("/dashboard/getsingleevent")
def get_single_event(id: int):
    return responseModel(message=f"{json.dumps(sqlite_get_single_event(id))}")


@app.post("/dashboard/createuser")
def create_user(user: userModel, response: Response):
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
def get_user(user: userModel, response: Response):
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
            await socket.send_text("received")
    except WebSocketDisconnect:
        logger.debug(f"{agent.username} has left")
    except Exception as e:
        logger.debug(f"error: {e}")
    finally:
        logger.debug("closing program, please wait")
        q.join()
        generated_token.remove(agent)
        MonitorList.remove(processmonitor)
