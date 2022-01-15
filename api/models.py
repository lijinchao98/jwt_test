from django.db import models

class UserInfo(models.Model):

    username = models.CharField(max_length=32)
    password = models.CharField(max_length=64)
    token = models.CharField(max_length=64,null=True,blank=True)

    class Meta:
        db_table = 'tb_userinfo'
        verbose_name = '用户信息'
        verbose_name_plural = verbose_name
