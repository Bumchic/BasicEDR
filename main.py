from fastapi import FastAPI


print('program running')
app = FastAPI()

@app.get('/')
async def root():
    return {"message": 'hello world'}

