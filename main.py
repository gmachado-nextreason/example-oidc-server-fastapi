'''OIDC server example'''

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from mangum import Mangum
from starlette.exceptions import HTTPException as StarletteHTTPException
from src.routes import router
from src.database import Base, engine
from src.oauth2 import config_oauth


app = FastAPI()

app.config = {
    'OAUTH2_JWT_ISS': 'https://authlib.org',
    'OAUTH2_JWT_KEY': 'secret-key',
    'OAUTH2_JWT_ALG': 'HS256',
    'OAUTH2_TOKEN_EXPIRES_IN': {
        'authorization_code': 300
    },
    'OAUTH2_ERROR_URIS': [
        ('invalid_client', 'https://developer.your-company.com/errors#invalid-client'),
    ]
}

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    '''Override the StarletteHTTPException exception'''
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )

Base.metadata.create_all(bind=engine)

config_oauth(app)

app.include_router(router)

handler = Mangum(app)
