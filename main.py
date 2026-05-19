from fastapi import FastAPI
from pydantic import BaseModel

class event(BaseModel):
    event: str


print('program running')
app = FastAPI()

@app.get('/')
async def root():
    return "test"

@app.post('/api/event')
async def receive_user_event(event: event):
    print(event.event)

