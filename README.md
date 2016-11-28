# mod_fence
## Version: 0.1 (alpha)

##### With mod_fence is under developing for reason to do guarding apache against DOS attacks and any known bugs.

In this early stage mod_fence is only can do the followings:

Try to kill stucked childs TESTED ON: (MPM_ITK, MPM_PREFORK) 

**Known PHP Bug is apache's children get stucked while PHP indefinitely try to access session file via FLOCK(...)**

## Configuration

````
<IfModule mod_fence.c>
  Fence_Enable          On
  Fence_ChildTimeout    3600 # Dont set it too small, because cause stucks
</IfModule>
````

## License
````

   Copyright 2016 Hlavaji Viktor / DaVieS
        nPulse.net / davies@npulse.net

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

````