

#   JWT学习

## 1、jwt是什么

```
json web token,一般用于任务认证（前后端分离/微信小程序/app开发）
```

### 基本认证流程

用户要登陆，发用户名密码，把请求发过去，用户名密码认证成功，服务器给用户发一个标识

* 以前，没写前后端分离，弄一个session随机字符串放到cookie里面，

* 前后端分离时候，认证成功后，会在服务器生成一个token（也是个随机字符串），然后把token返回给前端，以后用户再请求时，就带着这个token过来，服务器对这个token进行校验，



## 2、jwt实现过程

### 基于token认证的程序

 不用DRF也能写restful接口，只是DRF框架方便

#### 1.创建项目，app

```python
python manage.py startapp api
```

#### 2.注册app

settings.py里的INSTALLED_APPS里加入

```
'api.apps.ApiConfig',
'rest_framework',
```

可以输入rest，然后按tab键自动补全

#### 3.写路由urls

直接写在主路由里，也不include分发了

```python
path('api/login/',views.LoginView().as_view)
```

#### 4.写视图views

```python
from django.shortcuts import render
from rest_framework.views import APIView

class LoginView(APIView):
    """用户登录"""
    def post(self,request,*args,**kwargs):
        user = request.data.get('username')
        pwd = request.data.get('password')
```

写了一个登陆视图，继承自APIview，option+回车，自动导包

用户要post用户密码，写一个post，用户密码要存在数据库，models里面写一个模型类

#### 5.写模型类models

用户，密码，token（让他可以为空）

```python
from django.db import models

class UserInfo(models.Model):
    
    username = models.CharField(max_length=32)
    password = models.CharField(max_length=64)
    token = models.CharField(max_length=64,null=True,blank=True)
   
```

#### 6.设置数据库，迁移

在迁移之前要设置好数据库，数据库我用mysql

settings里面，找到DATABASES，把sqlite3改为mysql,按如下设置

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'HOST': '127.0.0.1', # 数据库主机
        'PORT':3306, # 数据库端口
        'USER':'root', # 数据库用户名
        'PASSWORD': 'XXXXXXXX', # 数据库用户密码
        'NAME':'apitest' # 数据库名字
    }
}
```

总的__ init __里面，也导入mysql，进行·设置

```python
import pymysql
pymysql.install_as_MySQLdb()
```

启动数据库，然后用命令行，或者可视化工具Navicat创建NAME为apitest的数据库（字符集utf8）

再在终端执行以下，进行迁移

```python
python manage.py makemigrations
python manage.py migrate
```

#### 7.添加几个数据

可以在navicate里添加

我发现也可以在pycharm右边的database数据库设置连接这个数据库

#### 8.再写views

import一下model, uuid,response

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from api import models
import uuid

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
```

#### 9.发送数据登陆试一下

再发之前，要到settings里面把csfr那一行注释掉

用postman发送post请求，得到返回的token值



#### 10.再写一个OrderView

通过'api/order'获得订单列表

那么get的时候，就要进行校验token

```python
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
```

![截屏2022-01-15 下午3.36.41](/Users/lijinchao/Desktop/截屏2022-01-15 下午3.36.41.png)

![截屏2022-01-15 下午3.37.18](/Users/lijinchao/Desktop/截屏2022-01-15 下午3.37.18.png)

![截屏2022-01-15 下午3.39.32](/Users/lijinchao/Desktop/截屏2022-01-15 下午3.39.32.png)

这是基于token的认证，不是jwt！

token保存在数据库了，当然也可以保存在缓存或者redis里面

还可以model里加一项有效时间，token过来时候检查一下，时间也检查一样

#### 11.token认证流程

```
用户登陆，服务端返回token，并将token保存在服务端，
以后用户再来访问时，需要携带token，服务端获取token后，再去数据库中获取token进行校验
```



### 基于jwt认证的程序

#### 1.jwt认证流程

```
用户登录，服务端给用户返回一个token（服务端不保存）
以后用户再来访问，需要携带token，服务端获取token后，再做token的校验（直接通过算法校验）

优势：token不用在服务端保存
```

#### 2.jwt实现过程

* 用户提交用户名和密码给服务端，如果登陆成功，使用jwt创建一个token，并给用户返回

  * 第一段字符串，HEADER，内部包含了算法和类型（这个是固定的）

    转化成jason，然后做base64url加密（base64加密是可以反解的，先用base64加密，然后对加密的字符串中的+_用特殊字符替换）

  * 第二段字符串，PAYLOAD，自定义的值，第三行代表超时时间，也会转成json，做一个base64url加密

    这个可以被反解，不要放敏感信息，比如密码

  * 第三段字符串

    第一步：第1，2部分密文拼接起来

    第二步：对前2部分密文进行HS256加密 + 加盐（HS256不能反解）

    第三步：再做base64url加密

  ![截屏2022-01-15 下午4.14.34](/Users/lijinchao/Desktop/截屏2022-01-15 下午4.14.34.png)

​							[官网](jjwt.io)可以看到，jwt生成的token说由三段字符串组成，并可用"."连接起来

* 以后用户再来访问，需要携带token，后段需要对token进行校验

  * 获取token
  * 第一步：对token进行切割
  * 第二步：对第二段进行base64url解密，并获取payload信息，检测token是否已经过时
  * 第三步：把1,2段拼接，再次执行hs256加密，加盐。密文 = base64解密（第三段），如果相等，表示token未被修改过（认证通过）

  你可以改token，但是你不知道盐！！

  官网可以看到

  ```python
  pip install pyjwt==1.7.1
  如果不选，会装最新版本，一些东西不太一样，还是装这个旧的吧
  ```

  ```python
  # views.py
  
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
  ```

  ```python
      # url中添加以下
      
      path('api/jwt/login/',views.JwtLoginView().as_view()),
      path('api/jwt/order/',views.JwtOrderView().as_view()),
  ```

  

![截屏2022-01-15 下午10.35.33](/Users/lijinchao/Desktop/截屏2022-01-15 下午10.35.33.png)

![截屏2022-01-15 下午10.36.05](/Users/lijinchao/Desktop/截屏2022-01-15 下午10.36.05.png)

![截屏2022-01-15 下午10.38.18](/Users/lijinchao/Desktop/截屏2022-01-15 下午10.38.18.png)

![截屏2022-01-15 下午10.38.40](/Users/lijinchao/Desktop/截屏2022-01-15 下午10.38.40.png)

#### 3.企业版本

上面jwt实现看起来乱，再写一个企业版本

url

```python
path('api/pro/login/',views.ProLoginView().as_view()),
path('api/pro/order/',views.ProOrderView().as_view()),
```

写一个drf的认证组件，api下，新建extensions目录，新建auth.py

再一个utils目录(工具)，新建jwt_auth.py

auth.py

```python
from rest_framework.authentication import  BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from jwt import exceptions
from django.conf import  settings


# 表示url传token  这是固定的写法
class JwtQueryParamsAuthentication(BaseAuthentication):

    def authenticate(self, request):
        #这个可以灵活修改，token传在请求头，其他地方，可以改
        token = request.query_params.get("token")  # 从url中获取token，比如/api/order/?token=22121
        # token = request._request.get("token")   #从上一个request中获取token

        # 1.切割
        # 2.解密第二段/判断过期
        # 3.验证第三段合法性
        salt = settings.SECRET_KEY
        payload = None
        msg = None
        try:
            payload = jwt.decode(token, salt, True)  # True表示校验（时间，第三段合法性）
        except exceptions.ExpiredSignatureError:
            msg = 'token已失效'
            raise AuthenticationFailed({'code':1003,'error':"token已失效"})
        except jwt.DecodeError:
            msg = 'token认证失败'
            raise AuthenticationFailed({'code':1003,'error':"token认证失败"})
        except jwt.InvalidTokenError:
            msg = '非法的token'
            raise AuthenticationFailed({'code':1003,'error':"非法的token"})

        # 三种操作
        # 1、抛出异常，后续不再执行
        # 2、return一个元组 （1，2），认证通过，在视图中如果调用request.user就是元组的第一个值，request.auth就是元组的第二个值
        # 3、None
        return (payload, token
```

jwt_auth

```python
import jwt
import datetime
from django.conf import  settings

def creat_token(payload,timeout=1):

    salt = settings.SECRET_KEY
    # 构造header,如果不写，默认下面这个
    headers = {
        'typ': 'jwt',
        'alg': 'HS256'
    }
    # 构造payload
    payload['exp']: datetime.datetime.utcnow() + datetime.timedelta(minutes=timeout)  # 超时时间
    token = jwt.encode(payload=payload, key=salt, algorithm="HS256", headers=headers)

    return token
```

views

```python
from api.utils.jwt_auth import creat_token

class ProLoginView(APIView):
    """企业版jwt用户登录"""
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
```

urls

```python
    path('api/pro/login/',views.ProLoginView().as_view()),
    path('api/pro/order/',views.ProOrderView().as_view()),
```

如果views里面，有很多个视图，都要认证，难道要每个class里面都写这么一行吗？

```python
authentication_classes = [JwtQueryParamsAuthentication,]
```

不用，可以直接写到settings里面

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES":['api.extensions.auth.JwtQueryParamsAuthentication',]
}
```

可以点开views里面的APIViews源码，看到配置文件是，DEFAULT_AUTHENTICATION_CLASSES

```python
class APIView(View):

    # The following policies may be set at either globally, or per-view.
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES
    parser_classes = api_settings.DEFAULT_PARSER_CLASSES
    
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    
    throttle_classes = api_settings.DEFAULT_THROTTLE_CLASSES
    permission_classes = api_settings.DEFAULT_PERMISSION_CLASSES
    content_negotiation_class = api_settings.DEFAULT_CONTENT_NEGOTIATION_CLASS
    metadata_class = api_settings.DEFAULT_METADATA_CLASS
    versioning_class = api_settings.DEFAULT_VERSIONING_CLASS
```

然后，每个视图都自动加了这个认证，所有页面都登陆成功才能访问，那么问题来了，登陆页面呢？也要登陆成功才能访问么。

解决：登陆视图，写上

```python
authentication_classes = []
```

## 3、应用

```
pip install pyjwt
```

```
pyjwt.encode 生成token
pyjwt.decode token解密
```

## 4、扩展

```
pip install djangorestframework-jwt
# 其实也是调用的pyjwt 建议不用这个 封装了其他的
# 建议用pyjwt
```

