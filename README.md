### 概述
标品方成功申请证书后，需要使用SDK校验标品的某些功能模块是否可用，证书中所包含的功能模块，允许用户访问使用，证书中不包含的功能模块，标品方通过SDK校验后，需要进行拦截，不允许使用该功能模块


### SDK使用方法

### 1 安装
```bash
pip install license-sdk-python
```

### 2 SDK类型说明
```
# SDK初始化结果
class InitRes(object):
    result: bool # 初始化是否成功，true:成功，false:失败
    msg: str # 错误信息


// 模块树形结构
class Module(object):
    key: str # 模块key
    name: str # 模块名称
    issuedTime: str # 生效时间
    expireTime: str # 过期效期
    extra: str
    childFuncs: Modulelist

type Modulelist = List[Module]

class EventType(enum.Enum):
    LicenseChange = "license_change" # 证书变化事件，比如证书有效期的变更，权限树的修改等
    ConnectionError = "connection_error" # websocket连接异常事件
    LicenseExpiring = "license_expiring" # 证书即将过期事件
    LicenseRevoke = "license_revoke" # 证书吊销事件，证书吊销后，所有功能模块不可用
```

### 3 SDK方法说明
- init(endPoint: str, prodkey: str, secretKey: str) 初始化sdk
	- endPoint: 许可服务地址
	- prodkey: 标品id
	- secretKey: 密钥
- getModules() 获取标品的权限树
- getModule(String key)  获取指定key的权限树
- validate(String key) 校验证书是否有这个key的权限
- getRemainingDays() 获取证书剩余有效期天数

### 4 Client使用
```bash
from license_sdk_python import Client

# 初始化sdk客户端
client = Client("http://ip:port", "your prodkey", "your secret key") # secret key 向开发者获取  
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


days = client.getRemainingDays()
print("许可证书有效期剩余天数：", days)

def license_change_callback(data: Module):
    print("license_change_callback data: ", data)

def license_expiring_callback(data: any):
    # 返回结果示例 { day: 16 }
    print("license_expiring_callback data: ", data)

def license_revoke_callback(data: Module):
    print("license_revoke_callback data: ", data) 

def connection_error_callback(data: any): 
    # Error: connect ECONNREFUSED ::1:18080
    print("Error connection: ", data)

# 监听证书变化事件
client.on(EventType.LicenseChange, license_change_callback)

# 监听证书即将过期事件
client.on(EventType.LicenseExpiring, license_expiring_callback)

 # 监听证书撤销事件
client.on(EventType.LicenseRevoke, license_revoke_callback)

# 监听ws链接异常
client.on(EventType.ConnectionError, connection_error_callback)
    
```