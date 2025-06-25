# **CertSelector and CertLocator APIs**
# **Table of Contents**
- [Table of Contents](#certselectorandcertlocatorapis-tableofc)
- [Overview](#certselectorandcertlocatorapis-overview) 
  - [certLocator](#certselectorandcertlocatorapis-certloca)
  - [certSelector](#certselectorandcertlocatorapis-certsele)
- [Configuration and Properties](#certselectorandcertlocatorapis-configur) 
  - [hrot.properties](#certselectorandcertlocatorapis-hrot.pop)
  - [certsel.conf](#certselectorandcertlocatorapis-certsel.)
- [API Interfaces](#certselectorandcertlocatorapis-apiinter) 
  - [Cert Locator Data](#certselectorandcertlocatorapis-certloca) 
    - [Cert Locator Object](#certselectorandcertlocatorapis-certloca)
    - [Cert Locator Status](#certselectorandcertlocatorapis-certloca)
  - [Certificate Locator API's](#certselectorandcertlocatorapis-certific) 
    - [Cert Locator Object Constructor/Destructor](#certselectorandcertlocatorapis-certloca) 
      - [rdkcertlocator_t *rdkcertlocator_new( const char *config_path, const char *hrotprop_path );](#certselectorandcertlocatorapis-rdkcertl)
      - [rdkcertlocatorStatus_t rdkcrtlocator_free(rdkcertlocator_t **certloc );](#certselectorandcertlocatorapis-rdkcertl)
    - [OpenSSL Engine Selector](#certselectorandcertlocatorapis-openssle) 
      - [char *rdkcertlocator_getengine(rdkcertlocaotr_t *certloc );](#certselectorandcertlocatorapis-char*rdk)
    - [Cert Locator Locate Cert](#certselectorandcertlocatorapis-certloca) 
      - [rdkcertlocatorStatus_t rdkcertlocator_locateCert ( rdkcertlocator_t *thisCertLoc, const char *certRef, char *certUri, char *certPass );](#certselectorandcertlocatorapis-rdkcertl)
  - [CertSelector and CertLocator Design and Implementation Guild](#certselectorandcertlocatorapis-certsele) 
    - [Cert Selector Object](#certselectorandcertlocatorapis-certsele)
    - [Cert Selector Status](#certselectorandcertlocatorapis-certsele)
    - [Cert Selector Retry](#certselectorandcertlocatorapis-certsele)
    - [Cert Selector Code Design](#certselectorandcertlocatorapis-certsele)
    - [Cert Locator Code Design](#certselectorandcertlocatorapis-certsele)
  - [Certificate Selector API's](#certselectorandcertlocatorapis-certific) 
    - [Cert Selector Object Constructor/Destructor](#certselectorandcertlocatorapis-certsele) 
      - [rdkcertselector_t *rdkcertselector_new( const char *config_path, const char *hrotprop_path, const char *certGroup );](#certselectorandcertlocatorapis-rdkcerts)
      - [rdkcertselectorStatus_t rdkcrtselector_free(rdkcertselector_t **certsel );](#certselectorandcertlocatorapis-rdkcerts)
    - [OpenSSL Engine Selector](#certselectorandcertlocatorapis-openssle) 
      - [char *rdkcertselector_getengine(rdkcertselector_t *certsel );](#certselectorandcertlocatorapis-char*rdk)
    - [Cert Selector Get Cert](#certselectorandcertlocatorapis-certsele) 
      - [rdkcertselectorStatus_t rdkcertselector_getCert ( rdkcertselector_t *thisCertSel, char **certUri, char **certPass );](#certselectorandcertlocatorapis-rdkcerts)
    - [Cert Selector Set Status](#certselectorandcertlocatorapis-certsele) 
      - [rdkcertselector_retry_t rdkcertselector_setCurlStatus( rdkcertselector_t *thisCertSel, unsigned int curlStat, const char *logEndpoint );](#certselectorandcertlocatorapis-rdkcerts)
- [Cert Select API call sequence from Application](#certselectorandcertlocatorapis-certsele)
- [How to integrate](#certselectorandcertlocatorapis-howtoint)
- [Test Guidance](#certselectorandcertlocatorapis-certsele)
  - [Simple Tests](#certselectorandcertlocatorapis-certsele)
  - [Sequence Tests](#certselectorandcertlocatorapis-certsele)
- [References](#certselectorandcertlocatorapis-referanc)
# **Overview**
These modules provide C-based APIs for applications to leverage certificates provisioned on a device.  There are two separate but related libraries.
## **certLocator**

   1. provides the URI ( path or PKCS#11 token ) and passcode for a certificate
   1. implemented as a simple lookup table using a configuration file specific to the platform
## **certSelector**

   1. provides the logic to provide the best available certificate for a given purpose as quickly as possible
   1. if a preferred cert has been found to be invalid, then the next preferred cert will be returned and the first will not be attempted again until it is corrected
   1. abstracts away from component the details of accessing SE, TEE, or filesystem
   1. provides selection logic for OpenSSL provider
   1. provides data in needed format whether OpenSSL or curl, etc.

Both libraries use platform specific data from a config file.  The APIs work as a generic filter between the config file and the components that use it.  The API modules can then be shared among various platforms with various requirements without platform specific logic.  The config files contain the platform specific details of where the certificates are located, how they can be accessed, and what to try next on a cert failure.  The APIs store state for a given instance so that once a certificate is found to be invalid, it will not be returned unless it has been updated.  The states are not help globally, so each component will assess the availability and validity of certs.

# **Configuration and Properties**
## **hrot.properties**
The provisioned certificates will vary based on the device model and its capabilities. The ***hrot.properties*** file should be installed in the /etc/ssl/certs/ directory to denote the device’s capabilities and engine usage for Hrot supported devices. Each device which supports Hrot must specify the OpenSSL provider in the hrot.properties file.  Example: 

- `hrotengine=<OpenSSL engine>`
## **certsel.conf**
The ***certsel.conf*** configuration file must be installed on the device, which lists all the available certificates for the device.  The default location for the file is /etc/ssl/certs. The order in-which the cert files are populated in the ***certsel.conf*** files must be set based on the selection order of the certs.  Both the certSelector and the certLocator APIs refer to the ***certsel.conf*** file.

The format is:

- `<usage group>, <cert reference>, <cert type>, <cert URI>, <credential reference>`

Where:

- <usage group> indicates the connection for which the certificate will be used. This will be a string (e.g., “CURL\_MTLS”, “CURL\_RED”, “CURL\_D2D”, "SRVR\_TLS" etc.).  A single usage group MUST not include the characters ',' or '|' 
  - Note: more than one usage group can be combined, separated by '|', eg. "CURL\_MTLS|CURL\_RED"
- <cert reference> is a string used by a component to request a specific certificate using the certLocator API. A cert reference MUST not include the character ','. 
  - Details TBD, but it may be something like: "SEOPER\_P12", "TEEOPER\_P11", "FSOPER\_PEM"
- <cert type> indicates the OpenSSL certificate type (PEM, P12, or P11).
- <cert uri> will be either of the form: "[file:///path/to/cert]" or "pkcs11:model=PKCS#15 ... ;serial=3169531ea57ce62f;token=test"
- <credential reference> is the reference name used with RdkConfig to find the credential name

**Example *certsel.conf* file entries:**

|<p>***CURL\_MTLS,TEEOPER\_P11,P11,pkcs11:model=PKCS#15%20emulated;manufacturer=piv\_II;serial=3169531ea57ce62f;token=test,tokendata<br>CURL\_MTLS,SEOPER\_P12,P12,[file:///opt/certs/devicecert_2.pk12,oper2data]<br>CURL\_MTLS,FSOPER\_P12,P12,[file:///opt/certs/devicecert_1.pk12,oper1data]<br>CURL\_MTLS,FSOPER\_PEM,PEM,[file:///opt/certs/devicecert_1.pem,oper1data]<br>CURL\_MTLS,FWFALLBK,P12,[file:///etc/ssl/certs/staticCrt.pk12,fallbkdata]<br>MQTT\_TLS,SEOPER\_P12,PEM,[file:///opt/certs/devicecert_2.pem,oper2data]<br>CURL\_RED,FWRED\_P12,P12,[file:///etc/ssl/certs/statered.p12,reddata***]***</p><p>***SRVR\_TLS,SESRVR\_P12,P12,[file:///opt/certs/devicecert_2.pk12,oper2data***]***</p>|
| :-: |

The library will retrieve relevant information from the config file to process the API requests.  The certSelector API maintains state in an instance to store the index into certificate list, last known validity of the certificates and last modification time for an accessed certificate.  Failed certs that have yet to be replaced will not be returned as a certificate to try.

# **API Interfaces**
The following defines the APIs for the certificate selector.
## **Cert Locator Data**
### **Cert Locator Object**
The cert locator object is accessed via interface via handle “***rdkcertlocator\_t***”. The constructor API will create an instance to hold the state information used to access the certsel.conf file.  
### **Cert Locator Status** 
- `certlocatorOk`  
- `certlocatorGeneralFailure`  
- `certlocatorBadPointer`  
- `certlocatorFileError`  
- `certlocatorFileNotFound`  
- `certlocatorCrtNotValid`  
- `certlocatorNotSupported`  
## **Certificate Locator API's**
### **Cert Locator Object Constructor/Destructor**
#### ***rdkcertlocator\_t \*rdkcertlocator\_new( const char \*config\_path, const char \*hrotprop\_path );***
This function is a constructor for the Certificate Locator Object. The Cert Locator object maintains the location of the config files.  The object must be destroyed after use by using rdkcertlocator\_free( ).

The other APIs require the pointer returned from 'new'.  The memory must be maintained by the calling component.  The internal states maintained by the certlocator object are:

1. the location of the file containing the list of certificates in the priority order
1. the location of the file containing the hrot properties needed for the OpenSSL engine
1. what is the certificate and passcode to be used

If either config\_path or hrotprop\_path are NULL, the default locations will be used.  The arguments can be entered as DEFAULT\_CONFIG or DEFAULT\_HROT.  The default locations will be:

1. /etc/ssl/certs/certsel.conf
1. /etc/ssl/certs/hrot.properties

*Component owners may chose to use the default locations, but during developer testing or component testing, alternative paths may be used.*

*Example: rdkcertlocator\_t \*mycertloc = rdkcertlocator\_new( "/etc/cert/certsel.conf", "/etc/certs/hrot.properties", "CURL\_MTLS" );*
#### **rdkcertlocatorStatus\_t rdkcrtlocator\_free(rdkcertlocator\_t \*\*certloc );**
This function is a destructor for the Certificate Locator Object. It should be called when the Certificate Locator Object is no longer needed. The function requires the handle to the Certificate Locator Object (rdkcertlocator\_t) as an argument. Upon execution, it wipes clean and releases the resources associated with the object. The component must invoke this function as soon after finishing with the data as possible.

The pointer will be set to NULL upon return.
### **OpenSSL Engine Selector**
#### **char \*rdkcertlocator\_getengine(rdkcertlocaotr\_t \*certloc );**
This function is used to select the OpenSSL engine based on the device’s hardware capabilities. If the certificate used for Mutual TLS (MTLS) communication is stored in the Hardware Security Module (HSM, Secure element in the device), an engine must be set to curl options to authenticate this certificate. The function will return the engine to be used in curl options CURLOPT\_SSLENGINE. If the function return NULL, then the CURLOPT\_SSLENGINE\_DEFAULT option should be set. If application uses non-curl library then refer the interface document to take appropriate action.

The return pointer, points to memory in the rdkcertlocator\_t object so memory will be allocated and freed along with the object constructor and destructor.
### **Cert Locator Locate Cert**
#### **rdkcertlocatorStatus\_t rdkcertlocator\_locateCert ( rdkcertlocator\_t \*thisCertLoc, const char \*certRef, char \*certUri, char \*certPass );**
API is for the location of the certificate for this certificate reference.  The return value of this function signifies the success for 0 (certlocatorOk); or non-zero for failure of the API call. The specific error code can provide more information about the nature of the failure. For example, certlocatorFileNotFound indicates that no certificate for that cert reference could not be found. Refer to the rdkcertlocatorStatus\_t for a complete list of possible return values.

Note: cert references need to match between the config file and the component source, but there is no internal code that verifies the validity of a given reference.
## **Cert Selector Data**
### **Cert Selector Object**
The cert selector object is accessed via interface via handle “***rdkcertselector\_t***”. The constructor API will create an instance to hold the state information used to access the certsel.conf file.
Internal values include:
- `char certSel_path[PATH_MAX]`
- `char hrotProp_path[PATH_MAX]`
- `char certGroup[PARAM_MAX]`
- `char certUri[PATH_MAX]`
- `char certCred[PARAM_MAX]`
- `char certPass[PARAM_MAX]`
- `char hrotEngine[ENGINE_MAX]`
- `unsigned short state`
- `unsigned short certIndx`
- `unsigned long certStat0`
- `unsigned long certStat1`
- `unsigned long certStat2`
- `unsigned long certStat3`
- `unsigned long certStat4`
- `unsigned long certStat5`
### **assuming**
- `PATH_MAX 128`
- `PARAM_MAX 64`
- `ENGINE_MAX 16`
- `LIST_MAX 6`
  
Where
certSel_path is the path to the cert selector configuration file; it can be set by the constructor or left empty ( certSel_path[0] = '\0' ) to use the default location
hrotProp_path is the path to the hardware route of trust properties file; it can be set by the constructor or left empty ( certSel_path[0] = '\0' ) to use the default location
certGroup is the cert usage group for this instance; the API will search the config file for this usage group and only consider those URIs for selection
certUri[PATH_MAX] is the Uri string found in the config file using index, certIndx
certCred[PARAM_MAX] is the credential reference string found in the config file using index, certIndx
certPass[PARAM_MAX] is the password extracted from the credential file; this is filled in using "get" and cleared using "set status" and "free"
hrotEngine[ENGINE_MAX] is the hrot engine retrieved from the hrot properties file which is needed to properly configure the libCurl call
state is the internal state if the instance is ready to give the cert or ready to check the status
certIndx is the current cert index within all the certGroup found; certIndx of 'n' means the 'nth' certificate entry matching the requested certGroup
certStat<n> stores the fail status of cert <n>; when a cert fails due to a certificate reason, the file modification date is store in certStat so later the API can tell if the file has changed

where
PATH_MAX is the max size (including null terminator) of a path string or URI string (which might include more than a path)
PARAM_MAX is the max size (including null terminator) of other character parameters
ENGINE_MAX is the max size (including null terminator) of the hrot engine
LIST_MAX is the maximum number of entries allowed per certGroup; there are six certStat entries, 0 through 5 
### **Cert Selector Status** 
- `certselectorOk`  
- `certselectorGeneralFailure`  
- `certselectorBadPointer`  
- `certselectorFileError`  
- `certselectorFileNotFound`  
- `certselectorCrtNotValid`  
- `certselectorNotSupported`
### **Cert Selector Retry**
- `TRY_ANOTHER`  
- `NO_RETRY`
### **Cert Selector Code design**
  #### ***rdkcertselector\_t \*rdkcertselector\_new( const char \*config\_path, const char \*hrotprop\_path, const char \*certGroup );***
    if <config_path> is NULL, then set <config_path> to default path ( /etc/ssl/certs/certsel.conf )
    
    if <hrotprop_path> is NULL, then set <hrotprop_path> to default path ( /etc/ssl/certs/hrot.properties )
    
    certIndx = 0

    Search for <certGroup> in first field of config_path file for first occurrence

    if certGroup is found in config file, then

      allocate space for instance

      initialize certSel_path, hrotProp_path, certGroup from arguments

      initialize certUri, certCred from entry found in config file

      clear certPass and certStat[*]

      return instance

    else

      return NULL

    endif

#### **rdkcertselectorStatus\_t rdkcrtselector\_free(rdkcertselector\_t \*\*certsel );**
    if <certsel> is not NULL AND <*certsel> is not NULL, then

      wipe all instance memory

      free instance

      NULL *certsel

      return certselectorOk

    else

      return certselectorBadPointer

    endif

#### **rdkcertselectorStatus\_t rdkcertselector\_getCert ( rdkcertselector\_t \*thisCertSel, char \*\*certUri, char \*\*certPass );**
    if <thisCertSel> is NULL OR certUri is NULL OR certType is NULL OR certPass is NULL, then return certselectorBadPointer

      returnValue =certselectorFileNotFound

      while thisCertSel→certUri is NOT empty, do

        extract cert path from Uri

        if file DOES NOT exists at cert path, then

          increment certIndx

          find the next cert matching certGroup in the config file

          set thisCertSel→certUri and thisCedrtSel→certCred

          continue

        endif

        if certStat for this cert NOT zero, then

          get modification date for current cert

          if certStat for this certIndx is same as modification date for current cert, then

            increment certIndx

            find the next cert matching certGroup in the config file

            set thisCertSel→certUri and thisCedrtSel→certCred

            continue

          endif

        endif

        extract passcode from thisCertSel→certCred and store in thisCertSel→certPass

        clear certStat for this cert

        returnValue = certselectorOk

    end while

    return the returnValue 

#### **rdkcertselector\_retry\_t rdkcertselector\_setCurlStatus( rdkcertselector\_t \*thisCertSel, unsigned int curlStat, const char \*logEndpoint );**
    return value = NO_RETRY

    if <thisCertsel> is NULL, then log error and return return value

      wipe thisCertSel→certPass

        if curlStat is 0 (success), then

          if certIndx is NOT 0, then

            certIndx = 0

            set thisCertSel→certUri and thisCertSel→certCred from certIndx 0

          else

            certUri and certCred should already be correct 

          endif

        endif

        if curlStat is a certificate failure, then

          set notification for certificate manager to analyze cert and consider update

          get file path for current cert, certUri

          get modification time for current cert

          set certStat for this certIndx to modification date

          increment certIndx

          get next certificate

          if next cert found, then

            set certUri and certCred for next cert

            return value = TRY_ANOTHER

          else

            set credIndx to 0

          endif

        else

          since not a cert error, keep return value to NO_RETRY

        endif

    return the return value
### **Cert Locator Code design** 
#### **rdkcertlocatorStatus_t \_t rdkcertlocator\_getCert ( const char \_t \*certRef, char \*\*certType, char \*\*certUri, char \*\*certPass );**
    if certRef is NULL OR *certUri is NULL OR *certType is NULL OR *certPass is NULL, then log error and return 

      Using default certSel.conf file, search for a certificate reference, certRef

      if cert found, then

        Copy certUri, certType, and certPass to argument pointers

        return success

      else

        return No File Found

    endif
    
## **Certificate Selector API's**
### **Cert Selector Object Constructor/Destructor**
#### ***rdkcertselector\_t \*rdkcertselector\_new( const char \*config\_path, const char \*hrotprop\_path, const char \*certGroup );***
This function is a constructor for the Certificate Selector Object. The Cert Selector object maintains the states for iterating through available certificate options.  It must be destroyed after use by using rdkcertselector\_free( ).

The other APIs require the pointer returned from 'new'.  The memory must be maintained by the calling component.  The internal states maintained by the certselector object are:

1. the location of the file containing the list of certificates in the priority order
1. the location of the file containing the hrot properties needed for the OpenSSL engine
1. what is the certificate and passcode to be attempted
1. what certificates have been found invalid

If either config\_path or hrotprop\_path are NULL, the default locations will be used.  The default locations will be:

1. /etc/ssl/certs/certsel.conf
1. /etc/ssl/certs/hrot.properties

*Component owners may choose to use the default locations, but during developer testing or component testing, alternative paths may be used.*

*Example: rdkcertselector\_t \*mycertsel = rdkcertselector\_new( "/etc/cert/certsel.conf", "/etc/certs/hrot.properties", "CURL\_MTLS" );*
#### **rdkcertselectorStatus\_t rdkcrtselector\_free(rdkcertselector\_t \*\*certsel );**
This function is a destructor for the Certificate Selector Object. It should be called when the Certificate Selector Object is no longer needed. The function requires the handle to the Certificate Selector Object (rdkcertselector\_t) as an argument. Upon execution, it wipes clean and releases the resources associated with the object. The component must invoke this function as soon after finishing with the data as possible.

The pointer will be set to NULL upon return.
### **OpenSSL Engine Selector**
#### **char \*rdkcertselector\_getengine(rdkcertselector\_t \*certsel );**
This function is used to select the OpenSSL engine based on the device’s hardware capabilities. If the certificate used for Mutual TLS (MTLS) communication is stored in the Hardware Security Module (HSM, Secure element in the device), an engine must be set to curl options to authenticate this certificate. The function will return the engine to be used in curl options CURLOPT\_SSLENGINE. If the function return NULL, then the CURLOPT\_SSLENGINE\_DEFAULT option should be set. If application uses non-curl library then refer the interface document to take appropriate action.

The return pointer, points to memory in the rdkcertselector\_t object so memory will be allocated and freed along with the object constructor and destructor.
### **Cert Selector Get Cert**
#### **rdkcertselectorStatus\_t rdkcertselector\_getCert ( rdkcertselector\_t \*thisCertSel, char \*\*certUri, char \*\*certPass );**
API is for the selection of the best available certificate for this certificate group based on available information. API will check the availability of the cert in the list after verifying iteration index, existence of the cert file, and the status of the last connection.  The "status" of the certs are maintained as the file date of the cert that last failed due to a certificate failure.  When a file date is stored and that date is the same as the current file date of the cert, then the cert is considered "bad."  Otherwise, the cert might be missing, unknown or good.  If it is missing, then it is skipped.  If it is unknown, the connection is attempted with it as is the case when when it is thought good.  The return value of this function signifies the success for 0 (certselectorOk); or non-zero for failure of the API call. The specific error code can provide more information about the nature of the failure. For example, certselectorFileNotFound indicates that no certificate for that connection group could not be found. Refer to the rdkcertselectorStatus\_t for a complete list of possible return values.

For any new connection attempt, the getCert API will begin at the first cert listed even if previously the cert was missing or marked as bad.  If it exists and the bad cert file date is different from the existing cert, it will be attempted again, since it may have been updated.  Otherwise, it will skip missing or "bad" certs until it finds one that exists and is not marked as bad.
### **Cert Selector Set Status**
#### **rdkcertselector\_retry\_t rdkcertselector\_setCurlStatus( rdkcertselector\_t \*thisCertSel, unsigned int curlStat, const char \*logEndpoint );**
Function evaluates the curl connection status from the last curl connection attempt and returns whether to attempt with a different certificate or not.  Internal cert status may also be updated where appropriate.

If the curl return status indicates a certificate failure, then the function will return the status to 'try another' certificate.  In addition, notification will be sent to the certificate manager that the cert may need to be updated.  This notification will be in the form of a temporary file indicating which file should be evaluated.  The cert manager will be updated to read those notifications at a future time.

The argument logEndpont allows the connection logging to contain the endpoint of the connection.  It can be populated with the URL that is used for the curl connection, or an abbreviated form but that will still provide details of what connection succeeded or failed.
# **Cert Select API call sequence from Application**
```c
rdkcertselector_h thisCertSel = rdkcertselector_new(NULL, NULL, "CURL_MTLS");

...

curl_easy_init();
curl_easy_setopt();
char *engine = rdkcertselector_getengine(thisCertSel);
if (engine != NULL) {
    curl_easy_setopt(curl, CURLOPT_SSLENGINE, engine);
} else {
    curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
}

do {
    rdkcertselectorStatus_t certStat = rdkcertselector_getCert(thisCertSel, &certUri, &certPass);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, P12/PEM);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, cert);
    curl_easy_setopt(curl, CURLOPT_KEYPASSWD, password);
    curl_code = curl_easy_perform(curl);
} while (rdkcertselector_setCurlStatus(thisCertSel, curl_code, "https://end.point") == TRY_ANOTHER);

...

curl_easy_cleanup(curl);

...

rdkcertselector_free(&thisCertSel);
```

# **How to integrate**
Application should call the constructor get an "gCertSel"; could keep as a global in order not to change existing API's implementation.
As long as application does not call destructor, previous connection history is preserved.
|**Existing Call**|**Update require to make with Cert Library**|Description.|
| :- | :- | :- |
|curl = curl\_easy\_init();|<p>curl = curl\_easy\_init();</p><p>thisCertSel= rdkcertselector\_new(“curl”,gCertSel,”MTLS”,”P12”);</p>|Create a new connection instance.|
|curl\_easy\_perform(curl);|<p>do {   </p><p>` `rdkcertselector\_getCert( thisCertSel, certFile, credData);   </p><p>` `curl\_easy\_setopt(curl, CURLOPT\_SSLCERTTYPE, certType);</p><p>` `curl\_easy\_setopt(curl, CURLOPT\_SSLCERT, certFile);</p><p>` `curl\_easy\_setopt(curl, CURLOPT\_KEYPASSWD, credData);</p><p>` `curl\_code = curl\_easy\_perform(curl);</p><p>} while(rdkcertselector\_setCurlStatus( thisCertSel, curl\_code) == RETRY)</p>|<p>Get the cert & password. Set them using curl setopt API's.</p><p>curl\_easy\_perform will make the connection.</p><p>Set the connection status to cert selector for tracking.</p>|
|curl\_easy\_cleanup(curl);|<p>curl\_easy\_cleanup(curl);</p><p>*rdkcertselector\_free(&*thisCertSel*);*</p>|Application could call cert selector \_free the cert selcetor instance.|
||||

## **Test Guidance**
The following tests are suggested.   Some are more conducive to unit testing but other may be tested at the component level.  They are broken into two groups, Simple        Tests and Sequence Tests.

Testing can be done with simple file manipulation because real certs are not required for the API.  'curl' will not be called during these tests.  Touch a file to create    it or update the date on it.

  - `Valid Cert:`touch the file, use curl code of 0
  - `Cert goes bad:` file exists, use curl code of 91
  - `Cert is missing:` rm file
  - `Bad Cert is updated:` after bad curl code, sleep 1, touch cert file
  - `Missing cert is restored:` touch cert file

### **Simple Tests**
  - `Missing Cert Group:`
     Call constructor with an unknown certGroup and verify that 'new' returns a NULL and logs the error correctly
    
  - `Find First with Success:`
     Call 'new' it returns the instance; call 'getCert' and it gets the first one; call 'setCurlStatus' with success (0) and it returns NO_RETRY
    
  - `Find Second; First Fails:`
     Call 'new' it returns the instance; call 'getCert' to get first cert; call 'setCurlStatus' with cert failure ( 91 ) it return TRY_ANOTHER; call 'getCert' to get second; call 'setCurlStatus' with success (0), it returns NO_RETRY
    
  - `Find Second; First Previously Marked as Bad:`
    Using same setup from previous test (do not call 'free' after previous test) , call 'getCert' to get second cert; call 'setCurlStatus' with success (0), it returns NO_RETRY
    
  - `First Fails but Not Due To Cert Error:`
    Call 'new' it returns the instance; call 'getCert to get first' call 'setCurlStatus' with non-cert failure (1); it returns NO_RETRY; call getCert again and it returns   first again; call 'setCurlStatus' with success (0), return NO_RETRY
    
  - `Can't Find A Cert:`
    Call 'new' with unknown cert group, it returns NULL for instance
    
  - `All Bad:`
    Remove all cert files; call 'new' but get NULL;

### **Sequence Tests**
  - `First Goes Bad:`
    First cert goes bad; uses second; next try skips first
    
  - `First Goes Bad, Second is Missing:`
    Second goes missing; uses first anyway; first goes bad; uses third; next try skips to third
    
  - `First Is Bad, Then Gets Updated:`
    First goes bad; uses second; then first updated so uses first; next uses first
    
  - `First and Second Are Bad; Second Updated, then First Updated:`
    First and Second go bad; third is used; Second updated, uses second; first updated, uses first 
    
  - `All Go Bad; All Updated:`
    First goes bad, use second; second goes bad, use third; third goes bad, returns No File Found; Third updated, uses third; Second updated, uses second; First update, uses first

# **References** 
1. <https://curl.se/libcurl/c/curl_easy_perform.html>
1. <https://curl.se/libcurl/c/libcurl-errors.html>
