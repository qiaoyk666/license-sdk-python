### 使用方法

1 安装
```bash
pip install license-sdk-python
```

2 Client使用
```bash
from license_sdk_python import Client

# 初始化sdk客户端
client = Client("localhost:18080", "10002")  
initRes = client.init()
if (initRes.result == False):
    print(f'sdk client init failed: {initRes.msg}')
    return
print(f'sdk client init success: {initRes.result}')

# 获取权限树
modules = client.getModules()      
print("modules: ", modules)

# 获取指定key的权限树
module = client.getModule('10002.10002')
print("module: ", module)

# 校验指定key是否有权限
key = '10002.10002'
isok = client.validate(key) # True or False
if (isok == True):
    print(f'key: {key} has permission')
else:
    print(f'key: {key} has no permission')
```