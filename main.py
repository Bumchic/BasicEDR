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
import mysql.connector.cursor
from pydantic import BaseModel
from bs4 import BeautifulSoup
import logging
import pandas as pd
from sigma.rule import SigmaLogSource, SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon.sysmon import sysmon_pipeline
import yaml
import mysql.connector
from typing import Annotated
import random
import sqlite3
from sigma.backends.sqlite.sqlite import sqliteBackend
import json
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
    "CommandLine": 'text',
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
    "ParentCommandLine": 'text',
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


class ProcessRule:
    logged_events = []

    def __init__(self, Host: str, Port: int, agent: agentModel):
        self.Host = Host
        self.Port = Port
        self.agent = agent

    def CheckEvent(self, event: BeautifulSoup):
        event_json = {}

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

        event_json["EventID"] = get_text("EventID")
        event_json["Computer"] = get_text("Computer")
        event_json["EventRecordID"] = get_text("EventRecordID")
        event_json["TimeCreated"] = get_attribute("TimeCreated", "SystemTime")

        eventdata = event.find("EventData")
        if eventdata is not None:
            for data in eventdata.find_all("Data"):
                name = data.get("Name")
                event_json[name] = data.getText()

        sqlite_insert_event(self.agent.id, event_json)
        self.logged_events.append(event_json)
        

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


print("program running")
app = FastAPI()
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s:\n\t%(message)s"
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

MonitorList: list[ProcessRule] = []
rules: SigmaCollection
backend: sqliteBackend
with open("pipeline\\win-os-payload encoded PowerShell deployed (command).yaml") as f:
    data = yaml.full_load(f)
    string = yaml.dump(data)
    rules = SigmaCollection.from_yaml(string)
pipeline = sysmon_pipeline()
backend = sqliteBackend(pipeline)
backend.table = "events"
UserDB = "UserDB"
usertable = "user"
sqlite = sqlite3.connect(f"{UserDB}.db")
cursor = sqlite.cursor()
generated_token: list[agentModel] = []
cursor.execute(
    f"CREATE TABLE IF NOT EXISTS {usertable} (username VARCHAR(255), password VARCHAR(255))"
)
cursor.execute(
    f"CREATE TABLE IF NOT EXISTS {usertable} (username VARCHAR(255), password VARCHAR(255))"
)


def event_table_query() -> str:
    Query = f'CREATE TABLE IF NOT EXISTS {usertable} ('
    res = 'UserID integer'
    for category, datatype in Event_category.items():
        res += f', {category} {datatype}'
    Query = Query + res
    Query += ')'
    return Query
cursor.execute(event_table_query())

def sqlite_get_user(user: dict[str, str]) -> dict[str, str] | None:
    sql = f"Select rowid, * from {usertable} where username = ?"
    values = (user["username"],)
    cursor.execute(sql, values)
    user_res = cursor.fetchone()
    if user_res is None:
        return None
    return {
        "id": user_res[0],
        "username": user_res[1].__str__(),
        "password": user_res[2].__str__(),
    }

def sqlite_get_user_list() -> list[dict[str, str]] | None:
    sql = f"Select rowid, * from {usertable}"
    cursor.execute(sql)
    user_res = cursor.fetchall()
    if user_res is None:
        return None
    user_list = []
    for user in user_res:
        to_append_user ={
            'id': user[0],
            'username': user[1].__str__()
        }
        user_list.append(to_append_user)
    return user_list

def sqlite_create_user(user: dict[str, str]):
    username = user["username"]
    password = user["password"]
    sql = f"insert into {usertable}(username, password) values (?, ?)"
    value = (username, password)
    cursor.execute(sql, value)
    sqlite.commit()
    logger.debug("user inserted")


def sqlite_auth_user(user: dict[str, str]) -> bool:
    logger.debug(user["password"])
    sql = f"Select * from {usertable} where username = ? and password = ?"
    values = (
        user["username"],
        user["password"],
    )
    cursor.execute(sql, values)
    user_res = cursor.fetchone()
    if user_res is None:
        return False
    return True

def sqlite_insert_event(userid: int, event: dict[str, str]):
    column = 'UserID'
    value = f'{userid}'
    for category, item in event.items():
        column += f', {category}'
        value += f", '{item}'"
    Query = f"insert into {usertable}({column}) values ({value})"
    cursor.execute(Query)
    sqlite.commit()
    logger.debug('event inserted')
    pass

def parse_user(user: userModel) -> dict[str, str]:
    return {"username": user.username, "password": user.password}


@app.get("/")
async def root():
    return HTMLResponse(content="hello", status_code=200)


@app.get("/dashboard")
async def get_dashboard():
    dashboard = open("Dashboard.html", mode="r").read()
    return HTMLResponse(dashboard)

@app.get('/dashboard/getuserlist')
async def get_user_list():
    return responseModel(message=f'{json.dumps(sqlite_get_user_list())}')


@app.post("/dashboard/createuser")
async def create_user(user: userModel, response: Response):
    logger.debug(user)
    user_dict = parse_user(user)
    try:
        if sqlite_get_user(user_dict) is not None:
            response.status_code = status.HTTP_403_FORBIDDEN
            return responseModel(message="User already exist")
        sqlite_create_user(user_dict)
        response.status_code = status.HTTP_200_OK
        return responseModel(message="User successfully created")
    except Exception as e:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return responseModel(message=f"{e}")


@app.post("/auth")
async def get_user(user: userModel, response: Response):
    user_dict = parse_user(user)
    logger.debug(user_dict)
    if sqlite_auth_user(user_dict):
        characters = "abcdefghijklmnopqrstuvwxyz0123456789"
        token = "".join(random.choice(characters) for _ in range(8))
        founduser = sqlite_get_user(user_dict)
        assert founduser is not None
        agent = agentModel(founduser["id"], founduser["username"], token)
        generated_token.append(agent)
        response.status_code = status.HTTP_200_OK
        return responseModel(message=token)
    response.status_code = status.HTTP_403_FORBIDDEN
    return responseModel(message="credential invalid")
    pass


def get_token(socket: WebSocket, token: Annotated[str | None, Query()] = None):
    if token is None:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    found: bool = False
    for gen_token in generated_token:
        if token == gen_token.token:
            found = True
            break
    if found is False:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    return token


def get_generated_token_from_token(token: str) -> agentModel | None:
    for iter_token in generated_token:
        if token == iter_token.token:
            return iter_token
    return None


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
    try:
        while True:
            data = await socket.receive_json()
            data = eventModel(**data)
            event = parse_beautifulsoup(data)
            processmonitor.CheckEvent(event=event)
    except WebSocketDisconnect:
        logger.debug(f"{agent.username} has left")
    except Exception as e:
        logger.debug(f"error: {e}")
    finally:
        logger.debug(processmonitor.PrintDataFrame())
        generated_token.remove(agent)
        MonitorList.remove(processmonitor)


class SQL_Handler:
    def __init__(self) -> None:
        pass



