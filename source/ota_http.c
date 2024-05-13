#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <mbedtls/base64.h>
#include "ota_http.h"

#define HTTP_STATUS_PARTIAL_CONTENT   206
#define HTTP_HEADER_CONTENT_RANGE     "Content-Range"
#define HTTP_HEADER_CONTENT_RANGE_LEN (sizeof(HTTP_HEADER_CONTENT_RANGE) - 1)
#define MAX_RETRIES 5

const char *securityToken = NULL;
const char *controllerId = NULL;
const char *configDataUrl = NULL;
const char *deploymentBaseUrl = NULL;
const char *downloadArtifactUrl = NULL;
const char *actionId = NULL;
const int *filesize = NULL;

int OtaHttp_FileRequestInit(const char *fPath,
                            HTTPRequestInfo_t *request,
                            HTTPRequestHeaders_t *requestHeaders,
                            HTTPResponse_t *response,
                            const struct OtaHttpConf *cfg)
{
    if (!(fPath && request && requestHeaders && response && cfg))
    {
        return HTTPInvalidParameter;
    }

    memset(response, 0, sizeof(*response));
    memset(request, 0, sizeof(*request));
    memset(requestHeaders, 0, sizeof(*requestHeaders));

    request->pPath     = fPath;
    request->pathLen   = strlen(fPath);
    request->pHost     = "172.16.3.30:8443";
    request->hostLen   = strlen(cfg->hostName);
    request->pMethod   = HTTP_METHOD_GET;
    request->methodLen = sizeof(HTTP_METHOD_GET) - 1;

    /* Multiple requests during single connection.
     * That means HTTP1.1 is expected, HTTP1.0 won't work!
     */
    request->reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    /* Request and Response use the same buffer */
    requestHeaders->pBuffer   = cfg->dataBuf;
    requestHeaders->bufferLen = cfg->dataBufSize;
    response->pBuffer         = cfg->dataBuf;
    response->bufferLen       = cfg->dataBufSize;

    return HTTPClient_InitializeRequestHeaders(requestHeaders, request);
}

int OtaHttp_GetFileContent(const char *fPath, uint32_t offset, uint32_t size, void *data, const struct OtaHttpConf *cfg)
{
    HTTPResponse_t response;
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    int ret;

    if (!(fPath && data && cfg))
    {
        return -HTTPInvalidParameter;
    }

    if (size == 0)
        return 0;

    /* Buffer used for entire HTTP response must be larger
     * than requested size due to extra size for HTTP headers.
     */

    if (cfg->dataBufSize <= size)
    {
        return -HTTPInsufficientMemory;
    }

    ret = OtaHttp_FileRequestInit(fPath, &request, &requestHeaders, &response, cfg);
    if (ret != HTTPSuccess)
    {
        return -ret;
    }

    ret = HTTPClient_AddRangeHeader(&requestHeaders, offset, offset + size - 1);
    if (ret != HTTPSuccess)
    {
        return -ret;
    }

    ret = HTTPClient_Send(cfg->ti, &requestHeaders, NULL, 0, &response, 0);

    /* Should this hold? */
    /* assert(response.bodyLen == response.contentLength); */

    if (ret != HTTPSuccess)
    {
        return -ret;
    }
    else if (response.statusCode != HTTP_STATUS_PARTIAL_CONTENT)
    {
        return response.statusCode;
    }
    else if (response.contentLength > size)
    {
        return -HTTPInvalidResponse;
    }

    memcpy(data, response.pBody, response.contentLength);
    return response.contentLength;
}

/* Returns zero on success.
 * Returns negative value of erroneous HTTPStatus.
 * Returns positive value of unexpected HTTP response status code (e.g. 404).
 */

int OtaHttp_GetFileSize()//const char *fPath, uint32_t *fSize, const struct OtaHttpConf *cfg)
{
    /*HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    int ret;

    const char *contentRangeStr = NULL;
    size_t contentRangeStrLen   = 0;

    if (!(fPath && cfg))
    {
        return -HTTPInvalidParameter;
    }

    ret = OtaHttp_FileRequestInit(fPath, &request, &requestHeaders, &response, cfg);
    if (ret != HTTPSuccess)
    {
        return -ret;
    }

    

    ret = HTTPClient_AddRangeHeader(&requestHeaders, 0, 0);
    if (ret != HTTPSuccess)
    {
        return -ret;
    }



    ret = HTTPClient_Send(cfg->ti, &requestHeaders, NULL, 0, &response, 0);
    if (ret != HTTPSuccess)
    {
        return -ret;
    }
    else if (response.statusCode != HTTP_STATUS_PARTIAL_CONTENT)
    {
        return response.statusCode;
    }



    ret = HTTPClient_ReadHeader(&response, HTTP_HEADER_CONTENT_RANGE, HTTP_HEADER_CONTENT_RANGE_LEN, &contentRangeStr,
                                &contentRangeStrLen);
    if (ret != HTTPSuccess)
    {
        return -ret;
    }


    {
        char *endptr;
        char *str;
        unsigned long size;

    
        str = strchr(contentRangeStr, '/');
        if (str == NULL)
        {
            return -HTTPInvalidResponse;
        }

        str++;
        size = strtoul(str, &endptr, 10);

        
        if (!isspace((int)*endptr) || size == 0 || size >= UINT32_MAX)
        {
            return -HTTPInvalidResponse;
        }

        *fSize = (uint32_t)size;
    }*/

    return filesize;
}

// Post a device pre-provisioning request to the server and checks the response to verify the device was created.
int OtaHttp_PostDevicePreProvisionRequest(
                            const struct OtaHttpConf *cfg)
{
    int ret;
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    
    /*if (!(fPath && request && requestHeaders && response && cfg))
    {
        return HTTPInvalidParameter;
    }*/
    //controllerId = "dev01";
    char *authHeader;
    char *base64Credentials = base64_encode("admin:admin", strlen("admin:admin"));
    memset(&request, 0, sizeof(request));
    memset(&requestHeaders, 0, sizeof(requestHeaders));
    memset(&response, 0, sizeof(response));
    request.pPath     = "/rest/v1/targets";
    request.pathLen   = strlen(request.pPath);
    request.pHost     = "172.16.3.30:8443";
    request.hostLen   = strlen(request.pHost);
    request.pMethod   = HTTP_METHOD_POST;
    request.methodLen = sizeof(HTTP_METHOD_POST) - 1;

    /* Multiple requests during single connection.
     * That means HTTP1.1 is expected, HTTP1.0 won't work!
     */
    request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    /* Request and Response use the same buffer */
    requestHeaders.pBuffer   = cfg->dataBuf;
    requestHeaders.bufferLen = cfg->dataBufSize;
    response.pBuffer         = cfg->dataBuf;
    response.bufferLen       = cfg->dataBufSize;

    ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
    if (ret != HTTPSuccess)
    {
        return ret;
    }

    ret = HTTPClient_AddHeader(&requestHeaders, "Accept", strlen("Accept"), "application/hal+json", strlen("application/hal+json"));
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    asprintf(&authHeader, "Basic %s", base64Credentials);
    ret = HTTPClient_AddHeader(&requestHeaders, "Authorization", strlen("Authorization"), authHeader, strlen(authHeader));
    free(authHeader);
    free(base64Credentials);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    ret = HTTPClient_AddHeader(&requestHeaders, "Content-Type", strlen("Content-Type"), "application/json", strlen("application/json"));
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Headers set.\n");
    // Set the request body
    char requestBody[] = "[{\"controllerId\": \"dev01\",\"name\": \"iMXRT1060\",\"description\": \"NXP_MCU OTA\"}]";

    // Send the HTTP request
    ret = HTTPClient_Send(cfg->ti, &requestHeaders, requestBody, strlen(requestBody), &response, 0);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Pre-Provisioning Response: %s\n", response.pBuffer);
    // Check the status code of the HTTP response
    if (response.statusCode != 201)
    {
        return -HTTPInvalidResponse;
    }

   PRINTF("Status code checked: %d\n", response.statusCode);
    // Find the start and end of the JSON part in the response
    char *jsonStart = strchr(response.pBuffer, '{');
    if (jsonStart == NULL)
    {
        return -HTTPInvalidResponse;
    }

    // Find the end of the JSON part
    char *jsonEnd = jsonStart;
    int balance = 1;
    while (balance > 0)
    {
        jsonEnd++;
        if (*jsonEnd == '{')
        {
            balance++;
        }
        else if (*jsonEnd == '}')
        {
            balance--;
        }
    }
    jsonEnd++;
    // Calculate the length of the JSON part
    size_t jsonLength = jsonEnd - jsonStart;

    // Validate the JSON
    PRINTF("Validating JSON...\n");
    JSONStatus_t jsonResult = JSON_Validate(jsonStart, jsonLength);
    if (jsonResult != JSONSuccess)
    {
        return -HTTPInvalidResponse;
    }
    // Create a temporary string to hold the JSON
    char* jsonTemp = malloc(jsonLength + 1);
    if (jsonTemp == NULL)
    {
        return -HTTPParserInternalError;
    }
    memcpy(jsonTemp, jsonStart, jsonLength);
    jsonTemp[jsonLength] = '\0'; // Null-terminate the string

    // Print the JSON
    PRINTF("JSON: %s\n", jsonTemp);

    char *value;
    size_t valueLength;
    JSONTypes_t valueType;
    
   // Extract controllerId
    jsonResult = JSON_SearchT(jsonTemp, jsonLength, "controllerId", strlen("controllerId"), &value,  &valueLength, &valueType);
    //PRINTF("Controller ID: %.*s\n", valueLength, value);
    if (jsonResult != JSONSuccess)
    {
        return -HTTPInvalidResponse;
    }
    controllerId = strndup(value, valueLength);
    if (controllerId == NULL)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Controller ID: %s\n", controllerId);
    // Reset value and valueLength variables
    value = NULL;
    valueLength = 0;

    // Extract securityToken
    jsonResult = JSON_SearchT(jsonTemp, jsonLength, "securityToken", strlen("securityToken"), &value,  &valueLength, &valueType);
    //PRINTF("Security Token: %.*s\n", valueLength, value);
    if (jsonResult != JSONSuccess)
    {
        return -HTTPInvalidResponse;
    }
    securityToken = strndup(value, valueLength);
    if (securityToken == NULL)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Security Token: %s\n", securityToken);
    free(jsonTemp);
    PRINTF("Device Provisioning Successful...\n");
    return 0;

}

char* strndup(const char *s, size_t n)
{
    char* new = malloc(n+1);
    if (new) 
    {
        memcpy(new, s, n);
        new[n] = '\0';
    }
    return new;
}

char *base64_encode(const char *input, int length)
{
    size_t output_length = 0;
    // Calculate the size of the output buffer
    mbedtls_base64_encode(NULL, 0, &output_length, (unsigned char *)input, length);

    // Allocate memory for the output buffer
    char *output = (char *)malloc(output_length);
    if (output == NULL)
    {
        return NULL;
    }

    // Perform the base64 encoding
    if (mbedtls_base64_encode((unsigned char *)output, output_length, &output_length, (unsigned char *)input, length) != 0)
    {
        free(output);
        return NULL;
    }

    return output;
}

int OtaHttp_EnableTargetTokenAuth(const struct OtaHttpConf *cfg)
{
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    int ret;
    char *authHeader;
    char *base64Credentials = base64_encode("admin:admin", strlen("admin:admin"));

    if (!cfg)
    {
        return -HTTPInvalidParameter;
    }

    memset(&request, 0, sizeof(request));
    memset(&requestHeaders, 0, sizeof(requestHeaders));
    memset(&response, 0, sizeof(response));

    request.pPath = "/rest/v1/system/configs/authentication.targettoken.enabled";
    request.pathLen = strlen(request.pPath);
    request.pHost = "172.16.3.30:8443";
    request.hostLen = strlen(request.pHost);
    request.pMethod = HTTP_METHOD_PUT;
    request.methodLen = sizeof(HTTP_METHOD_PUT) - 1;
    request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    requestHeaders.pBuffer = cfg->dataBuf;
    requestHeaders.bufferLen = cfg->dataBufSize;
    response.pBuffer = cfg->dataBuf;
    response.bufferLen = cfg->dataBufSize;

    ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
    if (ret != HTTPSuccess)
    {
        return ret;
    }

    ret = HTTPClient_AddHeader(&requestHeaders, "Accept", strlen("Accept"), "application/hal+json", strlen("application/hal+json"));
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    asprintf(&authHeader, "Basic %s", base64Credentials);
    ret = HTTPClient_AddHeader(&requestHeaders, "Authorization", strlen("Authorization"), authHeader, strlen(authHeader));
    free(authHeader);
    free(base64Credentials);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    ret = HTTPClient_AddHeader(&requestHeaders, "Content-Type", strlen("Content-Type"), "application/json", strlen("application/json"));
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Headers set.\n");
    char requestBody[] = "{\"value\": true}";

    ret = HTTPClient_Send(cfg->ti, &requestHeaders, requestBody, strlen(requestBody), &response, 0);
    //PRINTF("HTTP request sent. Response: %s\n", response.pBuffer);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Enable Target Token Auth Response: %s\n", response.pBuffer);
        // Check the status code of the HTTP response
    if (response.statusCode != 200)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Status code checked: %d\n", response.statusCode);
    // Find the start and end of the JSON part in the response
    char *jsonStart = strchr(response.pBuffer, '{');
    if (jsonStart == NULL)
    {
        return -HTTPInvalidResponse;
    }

    // Find the end of the JSON part
    char *jsonEnd = jsonStart;
    int balance = 1;
    while (balance > 0)
    {
        jsonEnd++;
        if (*jsonEnd == '{')
        {
            balance++;
        }
        else if (*jsonEnd == '}')
        {
            balance--;
        }
    }
    jsonEnd++;
    // Calculate the length of the JSON part
    size_t jsonLength = jsonEnd - jsonStart;

    // Validate the JSON
    PRINTF("Validating JSON...\n");
    JSONStatus_t jsonResult = JSON_Validate(jsonStart, jsonLength);
    if (jsonResult != JSONSuccess)
    {
        return -HTTPInvalidResponse;
    }
    // Create a temporary string to hold the JSON
    char* jsonTemp = malloc(jsonLength + 1);
    if (jsonTemp == NULL)
    {
        return -HTTPParserInternalError;
    }
    memcpy(jsonTemp, jsonStart, jsonLength);
    jsonTemp[jsonLength] = '\0'; // Null-terminate the string

    // Print the JSON
    PRINTF("JSON: %s\n", jsonTemp);

    // Free the temporary string
    free(jsonTemp);

    // Search for the "value" field in the JSON
    char *value;
    size_t valueLength;
    JSONTypes_t valueType;
    jsonResult = JSON_SearchT(jsonStart, jsonLength, "value", strlen("value"), &value,  &valueLength, &valueType);
    if (jsonResult != JSONSuccess)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("Value: %.*s\n", valueLength, value);
    // Check the value of the "value" field
    if (strncmp(value, "true", valueLength) != 0)
    {
        return -HTTPInvalidResponse;
    }

    return 0;
}

// Register the device with the server and verify the response.
int OtaHttp_GetDeviceConfig(const struct OtaHttpConf *cfg)
{
    int retries = 0;
    while (retries < MAX_RETRIES)
    {
        PRINTF("\nRetry Count: %d", retries);
        HTTPRequestInfo_t request;
        HTTPRequestHeaders_t requestHeaders;
        HTTPResponse_t response;
        int ret;
        char *authHeader;
        //char *configDataLink;
        PRINTF("Verifying Validity of Parameters...\n");
        if (!(controllerId && securityToken && cfg))
        {
            return -HTTPInvalidParameter;
        }

        // Initialize the HTTP request
        memset(&request, 0, sizeof(request));
        memset(&requestHeaders, 0, sizeof(requestHeaders));
        memset(&response, 0, sizeof(response));

        char path[128];
        snprintf(path, sizeof(path), "/DEFAULT/controller/v1/%s", controllerId);
        request.pPath = path;
        request.pathLen = strlen(request.pPath);
        PRINTF("GET CONFIG PATH: %s\n", request.pPath);
        request.pHost = "172.16.3.30:8443";
        request.hostLen = strlen(request.pHost);
        request.pMethod = HTTP_METHOD_GET;
        request.methodLen = sizeof(HTTP_METHOD_GET) - 1;
        request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

        requestHeaders.pBuffer = cfg->dataBuf;
        requestHeaders.bufferLen = cfg->dataBufSize;
        response.pBuffer = cfg->dataBuf;
        response.bufferLen = cfg->dataBufSize;
        
        ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
        PRINTF("\nInitializing request headers... Statuss = %d", ret);
        if (ret != HTTPSuccess)
        {
            return ret;
        }
        ret = HTTPClient_AddHeader(&requestHeaders, "Accept", strlen("Accept"), "application/hal+json", strlen("application/hal+json"));
        PRINTF("\nAdding Accept Header... Status = %d", ret);
        if (ret != HTTPSuccess)
        {
            return -HTTPInvalidResponse;
        }
        authHeader = malloc(strlen("TargetToken ") + strlen(securityToken) + 1);
        if (authHeader == NULL)
        {
            // free(base64Credentials); // Remove this line
            return -HTTPInvalidResponse;
        }

        // Format authHeader without base64Credentials
        sprintf(authHeader, "TargetToken %s", securityToken);
        PRINTF("\nAuthHeader: %s\n", authHeader);
        ret = HTTPClient_AddHeader(&requestHeaders, "Authorization", strlen("Authorization"), authHeader, strlen(authHeader));
        PRINTF("\nAdding Authorization Header... Status = %d", ret);
        free(authHeader);
        // free(base64Credentials); // Remove this line
        if (ret != HTTPSuccess)
        {
            return -HTTPInvalidResponse;
        }
    
        // Send the HTTP request
        ret = HTTPClient_Send(cfg->ti, &requestHeaders, NULL, 0, &response, 0);
        PRINTF("\nSending HTTP request... Status = %d", ret);
        if (ret != HTTPSuccess)
        {
            // If the request failed, increment the retry counter
            retries++;
            PRINTF("\nHTTPClient_Send failed with status = %d, retrying...", ret);

            // Wait for a certain amount of time before the next attempt
            // The delay increases exponentially with each failed attempt
            for (volatile int delay = 0; delay < 1000000 * retries; delay++) {}
            continue;
        }

        PRINTF("\nGet Device Config Response: %s", response.pBuffer);
        // Check the status code of the HTTP response
        if (response.statusCode != 200)
        {
            return -HTTPInvalidResponse;
        }
        PRINTF("\nStatus code checked: %d", response.statusCode);
        
        // Find the start and end of the JSON part in the response
        char *jsonStart = strchr(response.pBuffer, '{');
        if (jsonStart == NULL)
        {
            return -HTTPInvalidResponse;
        }

        // Find the end of the JSON part
        char *jsonEnd = jsonStart;
        int balance = 1;
        while (balance > 0)
        {
            jsonEnd++;
            if (*jsonEnd == '{')
            {
                balance++;
            }
            else if (*jsonEnd == '}')
            {
                balance--;
            }
        }
        jsonEnd++;
        // Calculate the length of the JSON part
        size_t jsonLength = jsonEnd - jsonStart;

        // Validate the JSON
        PRINTF("Validating JSON...\n");
        JSONStatus_t jsonResult = JSON_Validate(jsonStart, jsonLength);
        PRINTF("\nJson Result: %d", jsonResult);
        if (jsonResult != JSONSuccess)
        {
            return -HTTPInvalidResponse;
        }
        // Create a temporary string to hold the JSON
        char* jsonTemp = malloc(jsonLength + 1);
        if (jsonTemp == NULL)
        {
            return -HTTPParserInternalError;
        }
        memcpy(jsonTemp, jsonStart, jsonLength);
        jsonTemp[jsonLength] = '\0'; // Null-terminate the string

        // Print the JSON
        PRINTF("\nJSON: %s\n", jsonTemp);

        // Free the temporary string
        free(jsonTemp);

        // Search for the "value" field in the JSON
        size_t configDataUrlLength;
        char *configData;
        JSONTypes_t valueType;
        JSONStatus_t configResult, deploymentResult;
        size_t deploymentBaseUrlLength;
        char *deploymentBase;
        // Search for the "href" field within "_links" -> "configData"
        configResult = JSON_SearchT(jsonStart, jsonLength, "_links.configData.href", strlen("_links.configData.href"), &configData, &configDataUrlLength, &valueType);
        PRINTF("\nConfig Result: %d", configResult);
        
        if (!isFirstRun) {
            deploymentResult = JSON_SearchT(jsonStart, jsonLength, "_links.deploymentBase.href", strlen("_links.deploymentBase.href"), &deploymentBase, &deploymentBaseUrlLength, &valueType);
            PRINTF("\nDeployment Result %d", deploymentResult);
        }

        deploymentResult = JSON_SearchT(jsonStart, jsonLength, "_links.deploymentBase.href", strlen("_links.deploymentBase.href"), &deploymentBase, &deploymentBaseUrlLength, &valueType);
        PRINTF("\nDeployment Result %d", deploymentResult);
        // If the deploymentBase link is found, print its URL and store it
        PRINTF("\nIs it First Run %d", isFirstRun);
        if(isFirstRun && jsonResult == JSONSuccess && configResult == JSONSuccess)
        {
            PRINTF("\nconfigData URL: %.*s\n", configDataUrlLength, configData);
            if (configDataUrl == NULL) {
                configDataUrl = strndup(configData, configDataUrlLength);
            }
            isFirstRun = false;
            break;

        }
        else if (!isFirstRun && jsonResult == JSONSuccess && deploymentResult != JSONSuccess)
        {
            retries++;
            PRINTF("\nDeploymentBaseUrl field not found, retrying...");
            if (deploymentBaseUrl != NULL) {
                free(deploymentBaseUrl);
                deploymentBaseUrl = NULL;
            }
            for (volatile int delay = 0; delay < 100000 * retries; delay++) {}
            continue;
        }
        //PRINTF("configData URL: %.*s\n", configDataUrlLength, configData);
        PRINTF("deploymentBase URL: %.*s\n", deploymentBaseUrlLength, deploymentBase);
        /*if (configDataUrl == NULL && configResult == JSONSuccess) {
            configDataUrl = strndup(configData, configDataUrlLength);
        }*/
        if(deploymentBaseUrl == NULL && deploymentResult == JSONSuccess)
        {
            deploymentBaseUrl = strndup(deploymentBase, deploymentBaseUrlLength);
        }
        if (deploymentBaseUrl != NULL && configDataUrl != NULL && !isactionRetrieved)
        {
            // Find the last occurrence of the '/' character
            char *lastSlash = strrchr(deploymentBaseUrl, '/');
            if (lastSlash == NULL)
            {
                PRINTF("Invalid deploymentBase URL\n");
                return -HTTPInvalidResponse;
            }

            char *nextSlashOrQuestionMark = strpbrk(lastSlash + 1, "/?");
            if (nextSlashOrQuestionMark == NULL)
            {
                nextSlashOrQuestionMark = deploymentBaseUrl + deploymentBaseUrlLength;
            }

            // Create a new string with the action ID
            int actionIdLength = nextSlashOrQuestionMark - (lastSlash + 1);
            actionId = strndup(lastSlash + 1, actionIdLength);
            if (actionId == NULL)
            {
                PRINTF("Failed to extract action ID\n");
                return -HTTPInvalidResponse;
            }

            PRINTF("Action ID: %s\n", actionId);
            isactionRetrieved = true;
            int questionMarkPosition = strcspn(deploymentBaseUrl, "?");

            // Create a new string that only includes the part of the URL before the '?'
            char *newDeploymentBaseUrl = strndup(deploymentBaseUrl, questionMarkPosition);
            if (newDeploymentBaseUrl == NULL)
            {
                PRINTF("Failed to modify deploymentBase URL\n");
                return -HTTPInvalidResponse;
            }

            // Free the old deploymentBaseUrl and assign the new one
            free(deploymentBaseUrl);
            deploymentBaseUrl = newDeploymentBaseUrl;

            PRINTF("New deploymentBase URL: %s\n", deploymentBaseUrl);
            break;
        }
        if (configDataUrl != NULL && deploymentBaseUrl != NULL && isactionRetrieved) {
            break;
        }
        
    }
    if (retries == MAX_RETRIES)
    {
        // If the maximum number of retries has been reached, return an error
        PRINTF("\nHTTPClient_Send failed or configDataUrl field not found after %d retries", retries);
        return -HTTPInvalidResponse;
    }

    return 0;
}


int OtaHttp_UpdateDeviceConfig(const struct OtaHttpConf *cfg)
{
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    int ret;
    char *authHeader;

    if (!(controllerId && securityToken && cfg && configDataUrl))
    {
        return -HTTPInvalidParameter;
    }

    // Initialize the HTTP request
    memset(&request, 0, sizeof(request));
    memset(&requestHeaders, 0, sizeof(requestHeaders));
    memset(&response, 0, sizeof(response));

    request.pPath = configDataUrl;
    request.pathLen = strlen(request.pPath);
    request.pHost = "172.16.3.30:8443";
    request.hostLen = strlen(request.pHost);
    request.pMethod = HTTP_METHOD_PUT;
    request.methodLen = sizeof(HTTP_METHOD_PUT) - 1;
    request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    requestHeaders.pBuffer = cfg->dataBuf;
    requestHeaders.bufferLen = cfg->dataBufSize;
    response.pBuffer = cfg->dataBuf;
    response.bufferLen = cfg->dataBufSize;

    ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
    PRINTF("\nInitializing request headers... Statuss = %d", ret);
    if (ret != HTTPSuccess)
    {
        return ret;
    }

    ret = HTTPClient_AddHeader(&requestHeaders, "Accept", strlen("Accept"), "application/hal+json", strlen("application/hal+json"));
    PRINTF("\nAdding Accept Header... Status = %d", ret);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    authHeader = malloc(strlen("TargetToken ") + strlen(securityToken) + 1);
    if (authHeader == NULL)
    {
        return -HTTPInvalidResponse;
    }

    sprintf(authHeader, "TargetToken %s", securityToken);
    ret = HTTPClient_AddHeader(&requestHeaders, "Authorization", strlen("Authorization"), authHeader, strlen(authHeader));
    PRINTF("\nAdding Authorization Header... Status = %d", ret);
    free(authHeader);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    ret = HTTPClient_AddHeader(&requestHeaders, "Content-Type", strlen("Content-Type"), "application/json", strlen("application/json"));
    PRINTF("\nAdding Content-Type Header... Status = %d", ret);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    //hwRevision 1
    // Body of the PUT request
    const char *body = "{"
                       "  \"mode\": \"merge\","
                       "  \"data\": {"
                       "    \"VIN\": \"JH4TB2H26CC000001\","
                       "    \"hwRevision\": \"RT1060\""
                       "  },"
                       "  \"status\": {"
                       "    \"result\": {"
                       "      \"finished\": \"success\""
                       "    },"
                       "    \"execution\": \"closed\","
                       "    \"details\": []"
                       "  }"
                       "}";

    // Send the HTTP request
    ret = HTTPClient_Send(cfg->ti, &requestHeaders, body, strlen(body), &response, 0);
    PRINTF("\nSending HTTP request... Status = %d", ret);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    // Check the status code of the HTTP response
    if (response.statusCode != 200)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("\nStatus code checked: %d", response.statusCode);
    return 0;
}

int OtaHttp_VerifyServerUp(const struct OtaHttpConf *cfg)
{
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    int ret;

    PRINTF("Entering function...\n");

    if (!cfg)
    {
        PRINTF("Configuration is null, exiting function...\n");
        return false;
    }

    // Initialize the HTTP request
    PRINTF("Initializing HTTP request...\n");
    memset(&request, 0, sizeof(request));
    memset(&requestHeaders, 0, sizeof(requestHeaders));
    memset(&response, 0, sizeof(response));

    request.pPath = "/UI/login";
    request.pathLen = strlen(request.pPath);
    request.pHost = "172.16.3.30:8443";
    request.hostLen = strlen(request.pHost);
    request.pMethod = HTTP_METHOD_GET;
    request.methodLen = sizeof(HTTP_METHOD_GET) - 1;
    request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    requestHeaders.pBuffer = cfg->dataBuf;
    requestHeaders.bufferLen = cfg->dataBufSize;
    response.pBuffer = cfg->dataBuf;
    response.bufferLen = cfg->dataBufSize;

    PRINTF("Initializing request headers...\n");
    ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to initialize request headers, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }

    // Send the HTTP request
    PRINTF("Sending HTTP request...\n");
    ret = HTTPClient_Send(cfg->ti, &requestHeaders, NULL, 0, &response, 0);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to send HTTP request, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }
    PRINTF("Server Up Response: %s\n", response.pBuffer);

    // Check the status code of the HTTP response
    PRINTF("Checking status code of HTTP response...\n");
    if (response.statusCode != 200)
    {
        PRINTF("Invalid status code: %d\n", response.statusCode);
        return -HTTPInvalidResponse;
    }

    PRINTF("Exiting function with success.\n");
    return 0;
}

int OtaHttp_InspectDeploymentAction(const struct OtaHttpConf *cfg)
{
    int retries = 0;
    while (retries < MAX_RETRIES)
    {
        HTTPRequestInfo_t request;
        HTTPRequestHeaders_t requestHeaders;
        HTTPResponse_t response;
        int ret;
        char *authHeader;
        char path[256];

        if (!(controllerId && securityToken && cfg && deploymentBaseUrl))
        {
            return -HTTPInvalidParameter;
        }

        memset(&request, 0, sizeof(request));
        memset(&requestHeaders, 0, sizeof(requestHeaders));
        memset(&response, 0, sizeof(response));

        request.pPath = deploymentBaseUrl;
        request.pathLen = strlen(request.pPath);
        request.pHost = "172.16.3.30:8443";
        request.hostLen = strlen(request.pHost);
        request.pMethod = HTTP_METHOD_GET;
        request.methodLen = sizeof(HTTP_METHOD_GET) - 1;
        request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

        requestHeaders.pBuffer = cfg->dataBuf;
        requestHeaders.bufferLen = cfg->dataBufSize;
        response.pBuffer = cfg->dataBuf;
        response.bufferLen = cfg->dataBufSize;

        ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
        PRINTF("\nInitializing request headers... Statuss = %d", ret);
        if (ret != HTTPSuccess)
        {
            return ret;
        }

        ret = HTTPClient_AddHeader(&requestHeaders, "Accept", strlen("Accept"), "application/hal+json", strlen("application/hal+json"));
        PRINTF("\nAdding Accept Header... Status = %d", ret);
        if (ret != HTTPSuccess)
        {
            return -HTTPInvalidResponse;
        }

        authHeader = malloc(strlen("TargetToken ") + strlen(securityToken) + 1);
        if (authHeader == NULL)
        {
            return -HTTPInvalidResponse;
        }

        sprintf(authHeader, "TargetToken %s", securityToken);
        ret = HTTPClient_AddHeader(&requestHeaders, "Authorization", strlen("Authorization"), authHeader, strlen(authHeader));
        PRINTF("\nAdding Authorization Header... Status = %d", ret);
        free(authHeader);
        if (ret != HTTPSuccess)
        {
            return -HTTPInvalidResponse;
        }

        ret = HTTPClient_Send(cfg->ti, &requestHeaders, NULL, 0, &response, 0);
        PRINTF("\nSending HTTP request... Status = %d", ret);
        if (ret != HTTPSuccess)
        {   
            retries++;
            PRINTF("\nHTTPClient_Send failed with status = %d, retrying...", ret);
            for (volatile int delay = 0; delay < 1000000 * retries; delay++) {}
            continue;
        }
        if (response.statusCode != 200)
        {
            retries++;
            PRINTF("\nHTTP response status code not 200, retrying...");
            for (volatile int delay = 0; delay < 1000000 * retries; delay++) {}
            continue;
        }
        PRINTF("\nStatus code checked: %d", response.statusCode);
        
        // Find the start and end of the JSON part in the response
        char *jsonStart = strchr(response.pBuffer, '{');
        if (jsonStart == NULL)
        {
            return -HTTPInvalidResponse;
        }

        // Find the end of the JSON part
        char *jsonEnd = jsonStart;
        int balance = 1;
        while (balance > 0)
        {
            jsonEnd++;
            if (*jsonEnd == '{')
            {
                balance++;
            }
            else if (*jsonEnd == '}')
            {
                balance--;
            }
        }
        jsonEnd++;
        // Calculate the length of the JSON part
        size_t jsonLength = jsonEnd - jsonStart;
        // Validate the JSON
        PRINTF("Validating JSON...\n");
        JSONStatus_t jsonResult = JSON_Validate(jsonStart, jsonLength);
        if (jsonResult != JSONSuccess)
        {
            return -HTTPInvalidResponse;
        }
        // Create a temporary string to hold the JSON
        char* jsonTemp = malloc(jsonLength + 1);
        if (jsonTemp == NULL)
        {
            return -HTTPParserInternalError;
        }
        memcpy(jsonTemp, jsonStart, jsonLength);
        jsonTemp[jsonLength] = '\0'; // Null-terminate the string

        // Print the JSON
        PRINTF("JSON: %s\n", jsonTemp);

        // Free the temporary string
        free(jsonTemp);
        JSONTypes_t valueType;
        char *artifact;
        size_t artifactLength;
        jsonResult = JSON_SearchT(jsonStart, jsonLength, "deployment.chunks[0].artifacts[0]", strlen("deployment.chunks[0].artifacts[0]"), &artifact, &artifactLength, &valueType);

        if (jsonResult != JSONSuccess)
        {
            retries++;
            PRINTF("\nJSON_SearchT failed, retrying...");
            for (volatile int delay = 0; delay < 1000000 * retries; delay++) {}
            continue;
        }
        char *filename, *downloadUrl, *md5sumUrl, *sizeStr;
        size_t filenameLength, downloadUrlLength, md5sumUrlLength, sizeStrLength;
        JSON_SearchT(artifact, artifactLength, "filename", strlen("filename"), &filename, &filenameLength, &valueType);
        //JSON_SearchT(artifact, artifactLength, "size", strlen("size"), &filesize, NULL, &valueType);
        
        JSON_SearchT(artifact, artifactLength, "size", strlen("size"), &sizeStr, &sizeStrLength, &valueType);
        JSON_SearchT(artifact, artifactLength, "_links.download-http.href", strlen("_links.download-http.href"), &downloadUrl, &downloadUrlLength, &valueType);
        JSON_SearchT(artifact, artifactLength, "_links.md5sum-http.href", strlen("_links.md5sum-http.href"), &md5sumUrl, &md5sumUrlLength, &valueType);

        char *extractedFilename = strndup(filename, filenameLength);
        downloadArtifactUrl = strndup(downloadUrl, downloadUrlLength);
        // Convert the size string to an integer
        filesize = atoi(sizeStr);
        char *extractedMd5sumUrl = strndup(md5sumUrl, md5sumUrlLength);

        PRINTF("Filename: %s\n", extractedFilename);
        PRINTF("Size: %d\n", filesize);
        PRINTF("Download URL: %s\n", downloadArtifactUrl);
        PRINTF("MD5SUM URL: %s\n", extractedMd5sumUrl);
        break;
    }

    if (retries == MAX_RETRIES)
    {
        PRINTF("\nHTTPClient_Send or JSON_SearchT failed after %d retries", retries);
        return -HTTPInvalidResponse;
    }
    return 0;
}

int OtaHttp_DownloadArtifact(const struct OtaHttpConf *cfg, uint32_t offset, uint32_t size, void *data)
{
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    int ret;
    char *authHeader;
    char rangeHeader[50];

    if (!(controllerId && securityToken && cfg && deploymentBaseUrl && downloadArtifactUrl))
    {
        return -HTTPInvalidParameter;
    }

    if (size == 0)
        return 0;

    if (cfg->dataBufSize <= size)
    {
        return -HTTPInsufficientMemory;
    }

    memset(&request, 0, sizeof(request));
    memset(&requestHeaders, 0, sizeof(requestHeaders));
    memset(&response, 0, sizeof(response));

    request.pPath = downloadArtifactUrl;
    request.pathLen = strlen(request.pPath);
    request.pHost = "172.16.3.30:8443";
    request.hostLen = strlen(request.pHost);
    request.pMethod = HTTP_METHOD_GET;
    request.methodLen = sizeof(HTTP_METHOD_GET) - 1;
    request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    requestHeaders.pBuffer = cfg->dataBuf;
    requestHeaders.bufferLen = cfg->dataBufSize;
    response.pBuffer = cfg->dataBuf;
    response.bufferLen = cfg->dataBufSize;

    ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
    PRINTF("\nInitializing request headers... Statuss = %d", ret);
    if (ret != HTTPSuccess)
    {
        return ret;
    }

    authHeader = malloc(strlen("TargetToken ") + strlen(securityToken) + 1);
    if (authHeader == NULL)
    {
        return -HTTPInvalidResponse;
    }

    sprintf(authHeader, "TargetToken %s", securityToken);
    ret = HTTPClient_AddHeader(&requestHeaders, "Authorization", strlen("Authorization"), authHeader, strlen(authHeader));
    PRINTF("\nAdding Authorization Header... Status = %d", ret);
    free(authHeader);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    
    sprintf(rangeHeader, "bytes=%u-%u", offset, offset + size - 1);
    ret = HTTPClient_AddHeader(&requestHeaders, "Range", strlen("Range"), rangeHeader, strlen(rangeHeader));
    PRINTF("\nAdding Range Header... Status = %d", ret);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }

    ret = HTTPClient_Send(cfg->ti, &requestHeaders, NULL, 0, &response, HTTP_REQUEST_TIMEOUT_MS);
    PRINTF("\nSending HTTP request... Status = %d", ret);
    if (ret != HTTPSuccess)
    {
        PRINTF("\nHTTPClient_Send failed with status = %d", ret);
        return -HTTPInvalidResponse;
    }

    if (response.contentLength > size)
    {
        PRINTF("\nInvalid content length: %d", response.contentLength);
        return -HTTPInvalidResponse;
    }
    else
    {
        memcpy(data, response.pBody, response.contentLength);
        PRINTF("\nData copied to buffer: %d", response.contentLength);
        return response.contentLength;
    }
}

int OtaHttp_SendFeedback(const struct OtaHttpConf *cfg, int status)
{
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    int ret;
    char *authHeader;
    char path[256];
    char body[256];

    memset(&request, 0, sizeof(request));
    memset(&requestHeaders, 0, sizeof(requestHeaders));
    memset(&response, 0, sizeof(response));

    if (!(deploymentBaseUrl && cfg))
    {
        return -HTTPInvalidParameter;
    }

    PRINTF("ti.send: %p", (void*)cfg->ti->send);
    PRINTF("Deployment base URl: %s", deploymentBaseUrl);
    //snprintf(path,"%s/feedback", deploymentBaseUrl);
    snprintf(path, sizeof(path), "%s/feedback", deploymentBaseUrl);
    PRINTF("Send feedback Path: %s", path);
    request.pPath = path;
    request.pathLen = strlen(request.pPath);
    request.pHost = "172.16.3.30:8443";
    request.hostLen = strlen(request.pHost);
    request.pMethod = HTTP_METHOD_POST;
    request.methodLen = sizeof(HTTP_METHOD_POST) - 1;
    request.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    requestHeaders.pBuffer = cfg->dataBuf;
    requestHeaders.bufferLen = cfg->dataBufSize;
    response.pBuffer = cfg->dataBuf;
    response.bufferLen = cfg->dataBufSize;

    ret = HTTPClient_InitializeRequestHeaders(&requestHeaders, &request);
    PRINTF("\nInitializing request headers... Statuss = %d", ret);
    if (ret != HTTPSuccess)
    {
        return ret;
    }

    authHeader = malloc(strlen("TargetToken ") + strlen(securityToken) + 1);
    if (authHeader == NULL)
    {
        return -HTTPInvalidResponse;
    }

    sprintf(authHeader, "TargetToken %s", securityToken);
    ret = HTTPClient_AddHeader(&requestHeaders, "Authorization", strlen("Authorization"), authHeader, strlen(authHeader));
    PRINTF("\nAdding Authorization Header... Status = %d", ret);
    free(authHeader);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    ret = HTTPClient_AddHeader(&requestHeaders, "Content-Type", strlen("Content-Type"), "application/json", strlen("application/json"));
     PRINTF("\nAdding Content Type Header... Status = %d", ret);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
   snprintf(body, sizeof(body),
    "{"
    "  \"id\": \"%s\","
    "  \"status\": {"
    "    \"result\": {"
    "      \"finished\": \"success\""
    "    },"
    "    \"execution\": \"closed\","
    "    \"details\": []"
    "  }"
    "}", actionId);
    PRINTF("Body :%s", body);
    ret = HTTPClient_Send(cfg->ti, &requestHeaders, body, strlen(body), &response, 0);
    PRINTF("\nSending HTTP request... Status = %d", ret);
    if (ret != HTTPSuccess)
    {
        return -HTTPInvalidResponse;
    }
    if (response.statusCode != 200)
    {
        return -HTTPInvalidResponse;
    }
    PRINTF("\nStatus code checked: %d", response.statusCode);
    return 0;
}

