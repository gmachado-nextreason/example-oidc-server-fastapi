'''OIDC server example'''

import time
from authlib.oauth2 import OAuth2Error
from fastapi import APIRouter, Request, Form, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from werkzeug.security import gen_salt
from src.oauth2 import authorization, require_oauth, generate_user_info
from src.database import db
from src.models import User, OAuth2Client

router = APIRouter()

templates = Jinja2Templates(directory='src/templates')


@router.get('/')
def home(request: Request):
    '''List all clients'''
    clients = db.query(OAuth2Client).all()  # pylint: disable=E1101
    return templates.TemplateResponse('home.html', {'request': request, 'clients': clients})


@router.get('/create_client')
def get_create_client(request: Request):
    '''Display form to create client'''
    return templates.TemplateResponse('create_client.html', {'request': request})


@router.post('/create_client')
def post_create_client(  # pylint: disable=R0913
        client_name: str = Form(...),
        client_uri: str = Form(...),
        grant_type: str = Form(...),
        redirect_uri: str = Form(...),
        response_type: str = Form(...),
        scope: str = Form(...),
        token_endpoint_auth_method: str = Form(...)):
    '''Create the client information'''
    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at
    )

    client_metadata = {
        'client_name': client_name,
        'client_uri': client_uri,
        'grant_types': grant_type.splitlines(),
        'redirect_uris': redirect_uri.splitlines(),
        'response_types': response_type.splitlines(),
        'scope': scope,
        'token_endpoint_auth_method': token_endpoint_auth_method
    }
    client.set_client_metadata(client_metadata)

    if token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.add(client)  # pylint: disable=E1101
    db.commit()  # pylint: disable=E1101

    return RedirectResponse(url='/', status_code=status.HTTP_303_SEE_OTHER)


@router.post('/oauth/authorize')
def authorize(
        request: Request,
        uuid: str = Form(...)):
    '''Provide authorization code response'''
    user = db.query(User).filter(User.uuid == uuid).first()  # pylint: disable=E1101

    if not user:
        user = User(uuid=uuid)
        db.add(user)  # pylint: disable=E1101
        db.commit()  # pylint: disable=E1101

    request.body = {
        'uuid': uuid
    }

    try:
        authorization.validate_consent_request(request=request, end_user=user)
    except OAuth2Error as error:
        return dict(error.get_body())

    return authorization.create_authorization_response(request=request, grant_user=user)


@router.post('/oauth/token')
def token(
        request: Request,
        grant_type: str = Form(...),
        scope: str = Form(None),
        code: str = Form(None),
        refresh_token: str = Form(None),
        code_verifier: str = Form(None),
        client_id: str = Form(None),
        client_secret: str = Form(None)):
    '''Exchange the authorization code to access token'''
    request.body = {
        'grant_type': grant_type,
        'scope': scope,
    }
    if grant_type == 'authorization_code':
        request.body['code'] = code
    elif grant_type == 'refresh_token':
        request.body['refresh_token'] = refresh_token

    if code_verifier:
        request.body['code_verifier'] = code_verifier

    if client_id:
        request.body['client_id'] = client_id

    if client_secret:
        request.body['client_secret'] = client_secret

    return authorization.create_token_response(request=request)


@router.post('/oauth/introspect')
def introspect_token(
        request: Request,
        token: str = Form(...),  # pylint: disable=W0621
        token_type_hint: str = Form(...)):
    '''Introspect the token using access token'''
    request.body = {}

    if token:
        request.body.update({'token': token})

    if token_type_hint:
        request.body.update({'token_type_hint': token_type_hint})

    return authorization.create_endpoint_response('introspection', request=request)


@router.post('/oauth/revoke')
def revoke_token(
        request: Request,
        token: str = Form(...),  # pylint: disable=W0621
        token_type_hint: str = Form(...)):
    '''Revoke the token using access token'''
    request.body = {}

    if token:
        request.body.update({'token': token})

    if token_type_hint:
        request.body.update({'token_type_hint': token_type_hint})

    return authorization.create_endpoint_response('revocation', request=request)


@router.get('/oauth/userinfo')
def userinfo(request: Request):
    '''Request user profile information'''
    with require_oauth.acquire(request, 'profile') as token:  # pylint: disable=W0621
        return generate_user_info(token.user, token.scope)
