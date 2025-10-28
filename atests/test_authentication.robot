*** Settings ***
Library     RequestsLibrary
Library     customAuthenticator.py
Variables   secretvar.py

*** Test Cases ***
Get With Auth
    [Tags]    get    get-cert
    ${auth}=    Create List    user    passwd
    Create Session    httpbin    https://httpbin.org    auth=${auth}    verify=${CURDIR}${/}cacert.pem
    ${resp}=    GET On Session    httpbin    /basic-auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Get With Custom Auth
    [Tags]    get
    ${auth}=    Get Custom Auth    user    passwd
    Create Custom Session    httpbin    https://httpbin.org    auth=${auth}    verify=${CURDIR}${/}cacert.pem
    ${resp}=    GET On Session    httpbin    /basic-auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Get With Digest Auth
    [Tags]    get    get-cert
    ${auth}=    Create List    user    pass
    Create Digest Session
    ...    httpbin
    ...    https://httpbin.org
    ...    auth=${auth}
    ...    debug=3
    ...    verify=${CURDIR}${/}cacert.pem
    ${resp}=    GET On Session    httpbin    /digest-auth/auth/user/pass
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


Get With Custom Auth with Robot Secrets
    [Tags]     robot-74    get
    Skip If    $SECRET_PASSWORD == "not-supported"
    ...    msg=robot version does not support secrets
    ${auth}=    Create List    user     ${SECRET_PASSWORD}
    Create Custom Session    httpbin    https://httpbin.org    auth=${auth}    verify=${CURDIR}${/}cacert.pem
    ${resp}=    GET On Session    httpbin    /basic-auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True

Get With Digest Auth with Robot Secrets
    [Tags]    robot-74    get    get-cert
    Skip If    $SECRET_PASSWORD == "not-supported"
    ...    msg=robot version does not support secrets
    ${auth}=    Create List    user    ${SECRET_PASSWORD}
    Create Digest Session
    ...    httpbin
    ...    https://httpbin.org
    ...    auth=${auth}
    ...    debug=3
    ...    verify=${CURDIR}${/}cacert.pem
    ${resp}=    GET On Session    httpbin    /digest-auth/auth/user/passwd
    Should Be Equal As Strings    ${resp.status_code}    200
    Should Be Equal As Strings    ${resp.json()['authenticated']}    True
