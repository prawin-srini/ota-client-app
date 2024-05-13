#ifndef _OTA_HTTP_H_
#define _OTA_HTTP_H_

#include "core_http_client.h"
#include "core_json.h"

#define HTTP_REQUEST_TIMEOUT_MS 5000 // Set the timeout to 5 seconds
struct OtaHttpConf
{
    /* Communication channel interface */
    const TransportInterface_t *ti;

    /* Buffer used for both request headers and response.
     * Must be large enough to hold requested chunk of data
     * together with the response headers.
     */
    void *dataBuf;
    size_t dataBufSize;

    /* Host name as appeared in the HTTP request header*/
    const char *hostName;
};
extern const char * securityToken;
extern const char * controllerId;
extern const char * configDataUrl;
extern const char * deploymentBaseUrl;
extern const char * downloadArtifactUrl;
extern const char * actionId;
extern const int * filesize;
static bool isFirstRun = true;
static bool isactionRetrieved = false;

int OtaHttp_FileRequestInit(const char *fPath,
                            HTTPRequestInfo_t *request,
                            HTTPRequestHeaders_t *requestHeaders,
                            HTTPResponse_t *response,
                            const struct OtaHttpConf *cfg);

int OtaHttp_GetFileContent(
    const char *fPath, uint32_t offset, uint32_t size, void *data, const struct OtaHttpConf *cfg);

int OtaHttp_GetFileSize();
//const char *fPath, uint32_t *fSize, const struct OtaHttpConf *cfg);

char *base64_encode(const char *input, int length);

char* strndup(const char *s, size_t n);

int OtaHttp_VerifyServerUp(const struct OtaHttpConf *cfg);

int OtaHttp_GetDeviceConfig( const struct OtaHttpConf *cfg);

int OtaHttp_EnableTargetTokenAuth(const struct OtaHttpConf *cfg);

int OtaHttp_PostDevicePreProvisionRequest(const struct OtaHttpConf *cfg);

int OtaHttp_UpdateDeviceConfig(const struct OtaHttpConf *cfg);

int OtaHttp_InspectDeploymentAction(const struct OtaHttpConf *cfg);

int OtaHttp_DownloadArtifact(const struct OtaHttpConf *cfg, uint32_t offset, uint32_t size,  void *data);

int OtaHttp_SendFeedback(const struct OtaHttpConf *cfg, int status);

#endif /* _OTA_HTTP_H_ */
