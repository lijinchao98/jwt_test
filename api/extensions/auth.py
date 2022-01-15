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
        return (payload, token)
