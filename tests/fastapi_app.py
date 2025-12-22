from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter(prefix="/v1")

@app.get('/ping')
def ping():
    return {'pong': True}

@router.post('/users/{user_id}')
def create_user(user_id: str):
    return {'id': user_id}

app.include_router(router)

