
import token

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query, Response, WebSocketException, status
from fastapi.responses import HTMLResponse
import mysql.connector.cursor
from pydantic import BaseModel
from bs4 import BeautifulSoup
import logging
import pandas as pd
from sigma.rule import SigmaLogSource, SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon.sysmon import sysmon_pipeline
from sigma.backends.splunk.splunk import SplunkBackend
import yaml
import mysql.connector
from typing import Annotated
import random




class eventModel(BaseModel):
    event: str

class userModel(BaseModel):
    username: str
    password: str

class responseModel(BaseModel):
    message: str

class ProcessRule:
    logged_events = []
    def __init__(self, Host:str, Port: int, token: str):
        self.Host = Host
        self.Port = Port
        self.token = token
    def CheckEvent(self, event: BeautifulSoup):
        event_json = {}
        def get_text(tag:str):
            foundtag = event.find(tag)
            if foundtag is not None:
                value = foundtag.getText()
                if value is not None:
                    return value
            return None
        def get_attribute(tag:str, attr: str):
            foundtag = event.find(tag)
            if foundtag is not None:
                value = foundtag.get(attr)
                if value is not None:
                    return value
            return None
        event_json['EventID'] = get_text('EventID')
        event_json['Computer'] = get_text('Computer')
        event_json['EventRecordID'] = get_text('EventRecordID')
        event_json['TimeCreated'] = get_attribute('TimeCreated', 'SystemTime')
        
        eventdata = event.find('EventData')
        if eventdata is not None:
            for data in eventdata.find_all('Data'):
                name = data.get('Name')
                event_json[name] = data.getText()

        self.logged_events.append(event_json)

        
    def PrintDataFrame(self):
        dataframe = pd.DataFrame(self.logged_events)
        dataframe['EventID'] = pd.to_numeric(dataframe['EventID'], errors= 'coerce')
        dataframe['TimeCreated'] = pd.to_datetime(dataframe['TimeCreated'], errors= 'coerce', utc=True)
        
        dataframe = dataframe.sort_values('TimeCreated').set_index('TimeCreated')
        logger.debug(dataframe)
        
        
        

def parse_beautifulsoup(event:eventModel) -> BeautifulSoup:
    soup = BeautifulSoup(event.event, features="xml")
    return soup

 
print('program running')
app = FastAPI()
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s:\n\t%(message)s'
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

MonitorList: list[ProcessRule] = []
rules:SigmaCollection
backend: SplunkBackend
with open('pipeline\\win-os-payload encoded PowerShell deployed (command).yaml') as f:
    data = yaml.full_load(f)
    string = yaml.dump(data)
    rules = SigmaCollection.from_yaml(string) 
pipeline = sysmon_pipeline()
backend = SplunkBackend(pipeline)
mySQL = mysql.connector.connect(host= '127.0.0.1',port= 3306, user = 'root', password = 'admin')
cursor = mySQL.cursor(cursor_class=mysql.connector.cursor.MySQLCursorDict)
UserDB = 'UserDB'
usertable = 'user'
generated_token: list[str] = []
cursor.execute(f"CREATE DATABASE IF NOT EXISTS {UserDB}")
cursor.execute(f'USE {UserDB}')
cursor.execute(f'CREATE TABLE IF NOT EXISTS {usertable} (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))')


def MySQL_get_user(user: dict[str, str]) -> dict[str, str] | None:
    cursor.execute(f'Use {UserDB}')
    sql = f'Select * from {usertable} where username = %s'
    values = (user['username'], )
    cursor.execute(sql, values)
    user_res = cursor.fetchone()
    if user_res is None:
        return None
    assert isinstance(user_res, dict)
    return {'username': user_res['username'].__str__(), 'password': user_res['password'].__str__()}


def MySQL_create_user(user: dict[str, str]):
        username = user['username']
        password = user['password']
        cursor.execute(f'USE {UserDB}')
        sql = f'insert into {usertable}(username, password) values (%s, %s)'
        value = (username, password)
        cursor.execute(sql, value)
        mySQL.commit()
        logger.debug('user inserted')

def MySQL_auth_user(user: dict[str, str]) -> bool:
    sql = f'Select * from {usertable} where username = %s and password = %s'
    values = (user['username'], user['password'], )
    cursor.execute(sql, values)
    user_res = cursor.fetchone()
    if user_res is None:
        return False
    return True

def parse_user(user: userModel) -> dict[str, str]:
    return {
        'username': user.username,
        'password': user.password 
    }




@app.get('/')
async def root():
    return HTMLResponse(content= 'hello',status_code= 200)

@app.get('/dashboard')
async def get_dashboard():
    dashboard = open('Dashboard.html', mode= 'r').read()
    return HTMLResponse(dashboard)

@app.post('/dashboard/createuser')
async def create_user(user: userModel, response: Response):
    logger.debug(user)
    user_dict = parse_user(user)
    try:
        if MySQL_get_user(user_dict) is not None:
            response.status_code = status.HTTP_403_FORBIDDEN
            return responseModel(message='User already exist')
        logger.debug('here')
        MySQL_create_user(user_dict)
        response.status_code = status.HTTP_200_OK
        return responseModel(message='User successfully created')
    except Exception as e:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return responseModel(message=f'{e}')


@app.post('/auth')
async def get_user(user:userModel, response: Response):
    user_dict = parse_user(user)
    if MySQL_auth_user(user_dict):
        characters = "abcdefghijklmnopqrstuvwxyz0123456789"
        token = ''.join(random.choice(characters) for _ in range(8))    
        generated_token.append(token)
        response.status_code = status.HTTP_200_OK
        return responseModel(message=token)
    response.status_code = status.HTTP_403_FORBIDDEN
    return responseModel(message='credential invalid')
    pass


def get_token(socket: WebSocket, token: Annotated[str | None, Query()] = None):
    if token is None:
        raise WebSocketException(code = status.WS_1008_POLICY_VIOLATION)
    return token

@app.websocket("/ws")
async def websocket_endpoint(socket: WebSocket, token: Annotated[str, Depends(get_token)]):
    await socket.accept()
    Host = socket.client
    assert Host is not None
    processmonitor = ProcessRule(Host.host, Host.port, token)
    MonitorList.append(processmonitor)
    try: 
        while True:
            data = await socket.receive_json()
            data = eventModel(**data)
            event = parse_beautifulsoup(data)
            processmonitor.CheckEvent(event= event)
    except WebSocketDisconnect:
        logger.debug(f"{socket.client} has left")
    except Exception as e:
        logger.debug(f"error: {e}")
    finally:
        await socket.close()
        generated_token.remove(processmonitor.token)
        MonitorList.remove(processmonitor)


class SQL_Handler:
    def __init__(self) -> None:
        pass

