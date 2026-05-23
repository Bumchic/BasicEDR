

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup
import logging
import pandas as pd
from sigma.rule import SigmaLogSource, SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon.sysmon import sysmon_pipeline
from sigma.backends.splunk.splunk import SplunkBackend
import yaml



class eventModel(BaseModel):
    event: str

class ProcessRule:
    logged_events = []
    rule = SigmaRule.from_yaml
    def __init__(self, Host:str, Port: int):
        self.Host = Host
        self.Port = Port
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
with open('pipeline\\win-os-payload encoded PowerShell deployed (command).yaml') as f:
    data = yaml.full_load(f)
    string = yaml.dump(data)
    rules = SigmaCollection.from_yaml(string) 
pipeline = sysmon_pipeline()
backend = SplunkBackend(pipeline)
logger.debug(f'result: {backend.convert(rules)}')


@app.get('/')
async def root():
    return HTMLResponse(200)

@app.websocket("/ws")
async def websocket_endpoint(socket: WebSocket):
    await socket.accept()
    Host = socket.client
    assert Host is not None
    processmonitor = ProcessRule(Host.host, Host.port)
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
        MonitorList.remove(processmonitor)


# @app.post('/api/event/process')
# async def receive_process_event(event: eventModel):
#     parsed_event = parse_beautifulsoup(event)
#     return

# @app.post('/api/event/process')
# async def receive_network_event(event: eventModel):
#     parsed_event = parse_beautifulsoup(event)
#     return

class SQL_Handler:
    def __init__(self) -> None:
        pass

