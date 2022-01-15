from typing import Type, List

from rest_framework.views import APIView
from rest_framework.response import Response
from api import models
from jwt import exceptions
import uuid
import jwt
import datetime

class LoginView(APIView):
    """用户登录"""
    def post(self,request,*args,**kwargs):
        user = request.data.get('username')
        pwd = request.data.get('password')

        user_object = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名或密码名错误'})

        random_string = str(uuid.uuid4())

        user_object.token = random_string
        user_object.save()
        return Response({'code':1001,'data':random_string})

class OrderView(APIView):

    def get(self,request,*args,**kwargs):
        token = request.query_params.get("token")   #从url中获取token，比如/api/order/?token=22121
        # token = request._request.get("token")   #从上一个request中获取token
        if not token:
            return Response({'code':2000,'error':"登陆成功之后才能访问"})
        user_object = models.UserInfo.objects.filter(token=token).first()
        if not user_object:
            return Response({'code':2000,'error':"token无效"})

        return Response('订单列表')

class JwtLoginView(APIView):
    """基于jwt用户登录"""
    def post(self,request,*args,**kwargs):
        user = request.data.get('username')
        pwd = request.data.get('password')

        user_object = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名或密码名错误'})

        #随便写一个salt，也可以用settings里的SECRET_KEY
        salt = 'sdajshdkjsabfjk2fsd83nf9'
        #构造header,如果不写，默认下面这个
        headers = {
            'typ':'jwt',
            'alg':'HS256'
        }
        #构造payload
        payload = {
            'user_id':user_object.id, #自定义用户ID
            'username':user_object.username, #自定义用户名
            'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=1) #超时时间
        }
        #生成token
        token = jwt.encode(payload=payload,key=salt,algorithm="HS256",headers=headers)


        return Response({'code':1001,'data':token})

class JwtOrderView(APIView):

    def get(self,request,*args,**kwargs):
        token = request.query_params.get("token")   #从url中获取token，比如/api/order/?token=22121
        # token = request._request.get("token")   #从上一个request中获取token

        #1.切割
        #2.解密第二段/判断过期
        #3.验证第三段合法性
        salt = 'sdajshdkjsabfjk2fsd83nf9' #盐跟上面一样，不能变
        payload = None
        msg = None
        try:
            payload = jwt.decode(token,salt,True)  #True表示校验（时间，第三段合法性）
        except exceptions.ExpiredSignatureError:
            msg = 'token已失效'
        except jwt.DecodeError:
            msg = 'token认证失败'
        except jwt.InvalidTokenError:
            msg = '非法的token'
        if not payload:
            return Response({'code':1003,'error':msg})

        print(payload['user_id'],payload['username'])
        return Response('订单列表')

from api.utils.jwt_auth import creat_token

class ProLoginView(APIView):
    """企业版jwt用户登录"""
    authentication_classes = []
    def post(self,request,*args,**kwargs):
        user = request.data.get('username')
        pwd = request.data.get('password')

        user_object = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名或密码名错误'})
        token = creat_token({'id':user_object.id,'name':user_object.username})
        return Response({'code':1001,'data':token})

from api.extensions.auth import JwtQueryParamsAuthentication

class ProOrderView(APIView):
    # 中间件，执行get方法前，先执行这个类
    authentication_classes = [JwtQueryParamsAuthentication,]
    def get(self,request,*args,**kwargs):
        print(request.user)
        return Response('订单列表')