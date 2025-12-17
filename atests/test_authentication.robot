*** Settings ***
Library     RequestsLibrary
Library     customAuthenticator.py
Resource    res_setup.robot
Variables   secretvar.py

*** Test Cases ***
Get With Auth
    [Tags]    get    get-cert
    ${auth}=    Create List    user    passwd
    Create Session    authsession    ${HTTP_LOCAL_SERVER}    auth=${auth}
    ${resp}=    GET On Session    authsession    /basic-auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Get With Custom Auth
    [Tags]    get
    ${auth}=    Get Custom Auth    user    passwd
    Create Custom Session    authsession    ${HTTP_LOCAL_SERVER}    auth=${auth}
    ${resp}=    GET On Session    authsession    /basic-auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Get With Digest Auth
    [Tags]    get    get-cert
    ${auth}=    Create List    user    pass
    Create Digest Session
    ...    authsession
    ...    ${HTTP_LOCAL_SERVER}
    ...    auth=${auth}
    ...    debug=3
    ${resp}=    GET On Session    authsession    /digest-auth/auth/user/pass
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Get With Auth with Robot Secrets
    [Tags]     robot-74    get    get-cert
    Skip If    $SECRET_PASSWORD == "not-supported"
    ...    msg=robot version does not support secrets
    ${auth}=    Create List    user     ${SECRET_PASSWORD}
    Create Session    httpbin    https://httpbin.org    auth=${auth}    verify=${CURDIR}${/}cacert.pem
    ${resp}=    GET On Session    httpbin    /basic-auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Get With Digest Auth with Robot Secrets
    [Tags]    robot-74    get    get-cert
    Skip If    $SECRET_PASSWORD == "not-supported"
    ...    msg=robot version does not support secrets
    ${auth}=    Create List    user    ${SECRET_PASSWORD}
    Create Digest Session
    ...    authsession
    ...    ${HTTP_LOCAL_SERVER}
    ...    auth=${auth}
    ...    debug=3
    ...    verify=${CURDIR}${/}cacert.pem
    ${resp}=    GET On Session    httpbin    /digest-auth/auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Session-less GET With Auth with Robot Secrets
    [Tags]    robot-74    get    get-cert    session-less
    Skip If    $SECRET_PASSWORD == "not-supported"
    ...    msg=robot version does not support secrets
    ${auth}=    Create List    user    ${SECRET_PASSWORD}
    ${resp}=    GET    https://httpbin.org/basic-auth/user/passwd    auth=${auth}    verify=${CURDIR}${/}cacert.pem
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Session-less POST With Auth with Robot Secrets
    [Tags]    robot-74    post    post-cert    session-less
    Skip If    $SECRET_PASSWORD == "not-supported"
    ...    msg=robot version does not support secrets
    ${auth}=    Create List    user    ${SECRET_PASSWORD}
    ${data}=    Create Dictionary    test=data
    ${resp}=    POST    https://httpbin.org/post    json=${data}    auth=${auth}    verify=${CURDIR}${/}cacert.pem
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['json']['test']}    data
