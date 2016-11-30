# mod_fence
## Version: 0.9b (beta)

#### Primary Tasks:
**This module has only one primary task to covering apache with additional fences to protect against:**

- [x] Hostname validity checking by https://tools.ietf.org/html/rfc3986
- [x] Unresponsible or very slow website (hitting F5 like shooting in Call Of Duty)
- [x] Also Good against many well known attacks like: slowloris
- [x] PHP/Session FLOCK() de-stucking, yes its destuck apache modules!

#### ** Currently Tested on Apache2.4 MPM_ITK / MPM_PREFORK **
##### Main advantage is very lightweight and uses Apache Core Libs.


## History:
- **Known PHP Bug is apache's children get stucked while PHP indefinitely try to access session file via FLOCK(...) that simply causes a lot of headache for me**
- **Continuously pressing F5 on website which is under heavy load is a lamer things and must be avoid**
- **On shared hosting slow or mysql (write_lock) stucked websites able to denial the service**
- **There is a method to kill the apache with connections from ADSL with small packets and does not need to flood**

## Configuration

````
<IfModule mod_fence.c>
    Fence_Enable          On
    Fence_ChildTimeout    3600
    Fence_MitigateSoftRequests 5
    Fence_MitigateHardRequests 15
</IfModule>
````

#### Configuration Parameters
- **Fence_Enable (On/Off)** *(Enables the module)*
- **Fence_ChildTimeout ((numeric) seconds)** *(Sends a SIGKILL to child if not responding within the time)*
- **Fence_MitigateSoftRequests ((numeric) requests)** *(Mitigate a single IP when stalled >= (1s) requests reach this limit at same time)*
- **Fence_MitigateHardRequests ((numeric) requests)** *(Mitigate a single IP when any requests reach this limit at same time)*

#### In case of Apache behind proxy
###### When Apache behind the proxy its recommended to resolv true IPs through X-Forwarded-For header. There are already some modules to doing that, like mod_rpaf2


## License
````
/*
   Copyright 2016 Hlavaji Viktor / DaVieS
        nPulse.net / davies@npulse.net
    
    Thanks to Systech Global Ltd (systech.hu) to actively support this project


   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
````