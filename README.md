# How to create an OpenID Connect 1.0 Provider

This is an example of OpenID Connect 1.0 server in [FastAPI](https://fastapi.tiangolo.com/) and [Authlib](https://authlib.org/).

- FastAPI Repo: <https://github.com/tiangolo/fastapi>
- Authlib Repo: <https://github.com/lepture/authlib>

---

## Take a quick look

This is a ready to run example, let's take a quick experience at first. To
run the example, we need to install all the dependencies:

    $ pip install -r requirements.txt

Set FastAPI and Authlib environment variables:

    # disable check https (DO NOT SET THIS IN PRODUCTION)
    $ export AUTHLIB_INSECURE_TRANSPORT=1

Create Database and run the development server:

    $ uvicorn main:app --host 127.0.0.1 --port 5000 --reload

Now, you can open your browser with `http://127.0.0.1:5000/`.

Before testing, we need to create a client:

![create a client](https://user-images.githubusercontent.com/290496/64176341-35888100-ce98-11e9-8395-fd4cdc029fd2.png)

**NOTE: YOU MUST ADD `openid` SCOPE IN YOUR CLIENT**

Let's take `authorization_code` grant type as an example. Visit:

```
curl -i -XPOST http://127.0.0.1:5000/oauth/authorize?client_id=OQ5k5Xh8XtfE3ecybl4QdSg2&response_type=code&scope=openid+profile&nonce=abc -F uuid=XXXXXXX
```

After that, you will be redirect to a URL. For instance:

```
HTTP/1.1 100 Continue

HTTP/1.1 302 Found
date: Tue, 06 Oct 2020 22:21:12 GMT
server: uvicorn
location: https://example.com/?code=RSv6j745Ri0DhBSvi2RQu5JKpIVvLm8SFd5ObjOZZSijohe0
content-length: 2
content-type: application/json
```

Copy the code value, use `curl` to get the access token:

```
curl -u "${CLIENT_ID}:${CLIENT_SECRET}" -XPOST http://127.0.0.1:5000/oauth/token -F grant_type=authorization_code -F code=RSv6j745Ri0DhBSvi2RQu5JKpIVvLm8SFd5ObjOZZSijohe0
```
