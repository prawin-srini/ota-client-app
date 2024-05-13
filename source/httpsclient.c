/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2017 NXP. Not a Contribution
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <stdlib.h>

#include "ota_http.h"
#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/sockets.h"
#include "httpsclient.h"
#include "lwip/netdb.h"
#include "fsl_debug_console.h"
#include "mbedtls/md5.h"
//#include "root_ca.h"
#include "server.h"
#include "mbedtls/sha256.h"
#include "mflash_drv.h"
#include "flash_partitioning.h"
#include "network_cfg.h"
#include "flash_helper.h"
#include "ota_config.h"
#include "stdio.h"


extern unsigned char root_ca_cer[];
extern unsigned int root_ca_cer_len;
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define DEBUG_LEVEL 0

/* Size of maximum HTTP data payload transfer.
 * Since flash erase is done on the fly with downloading
 * data, it makes things easier when this is multiple of
 * flash page size and less or equal to flash erase sector.
 */

#define OTA_HTTP_BLOCK_SIZE 2048

#if OTA_HTTP_BLOCK_SIZE > MFLASH_SECTOR_SIZE
#error "HTTP block size can not be greater than flash erase sector size"
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
static TLSDataParams tlsDataParams;

/* Buffer size is given by defined block size and some space
 * for HTTP headers
 */
static unsigned char https_buf[OTA_HTTP_BLOCK_SIZE + 4096];

/*******************************************************************************
 * Code
 ******************************************************************************/

/* Send function used by mbedtls ssl */
static int lwipSend(void *fd, unsigned char const *buf, size_t len)
{
    return lwip_send((*(int *)fd), buf, len, 0);
}

/* Send function used by mbedtls ssl */
static int lwipRecv(void *fd, unsigned char *buf, size_t len)
{
    return lwip_recv((*(int *)fd), (void *)buf, len, 0);
}

/*
static int _iot_tls_verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    char buf[1024];
    ((void)data);

    PRINTF("HTTPS CLIENT::\nCert veryfication requested for (Depth %d):\n", depth);
    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
    PRINTF("HTTPS CLIENT::%s", buf);

    return 0;
}
*/
#ifdef MBEDTLS_DEBUG_C
static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);

    PRINTF("HTTPS CLIENT::\r\n%s, at line %d in file %s\n", str, line, file);
}
#endif

int https_client_tls_init(const char *host, const char *service)
{
    int ret          = 0;
    const char *pers = "https_ota_demo";
    char vrfy_buf[512];
    bool ServerVerificationFlag = false;
    const mbedtls_md_info_t *md_info;

#ifdef PRINT_CERT_INFO
    /* requires high stack usage! */
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
#endif

    if (!host || !service)
    {
        return NULL_VALUE_ERROR;
    }

    mbedtls_ssl_init(&(tlsDataParams.ssl));
    mbedtls_ssl_config_init(&(tlsDataParams.conf));
    mbedtls_hmac_drbg_init(&(tlsDataParams.hmac_drbg));
    mbedtls_x509_crt_init(&(tlsDataParams.cacert));
    mbedtls_x509_crt_init(&(tlsDataParams.clicert));
    mbedtls_pk_init(&(tlsDataParams.pkey));

#if defined(MBEDTLS_DEBUG_C)
    /* Enable debug output of mbedtls */
    mbedtls_ssl_conf_dbg(&(tlsDataParams.conf), my_debug, NULL);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    PRINTF("\nhttps_client_tls_init()::Seeding the random number generator...");
    mbedtls_entropy_init(&(tlsDataParams.entropy));
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if ((ret = mbedtls_hmac_drbg_seed(&(tlsDataParams.hmac_drbg), md_info, mbedtls_entropy_func,
                                      &(tlsDataParams.entropy), (const unsigned char *)pers, strlen(pers))) != 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed  ! mbedtls_hmac_drbg_seed returned -0x%x", -ret);
        return NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }

    PRINTF("\nhttps_client_tls_init():: Loading the CA root certificate...");
    ret = mbedtls_x509_crt_parse(&(tlsDataParams.cacert), (const unsigned char *)mbedtls_test_ca_crt,
                                 mbedtls_test_ca_crt_len);
    if (ret < 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed ! mbedtls_x509_crt_parse returned -0x%x while parsing root cert", -ret);
        return NETWORK_X509_ROOT_CRT_PARSE_ERROR;
    }
    PRINTF("\nhttps_client_tls_init()::  ok (%d skipped)", ret);

    PRINTF("\nhttps_client_tls_init():: Loading the client cert. and key...");
    ret = mbedtls_x509_crt_parse(&(tlsDataParams.clicert), (const unsigned char *)mbedtls_test_cli_crt,
                                 mbedtls_test_cli_crt_len);
    if (ret != 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed !  mbedtls_x509_crt_parse returned -0x%x while parsing device cert", -ret);
        return NETWORK_X509_DEVICE_CRT_PARSE_ERROR;
    }
    PRINTF("\nhttps_client_tls_init():: ok");

    ret = mbedtls_pk_parse_key(&(tlsDataParams.pkey), (const unsigned char *)mbedtls_test_cli_key,
                               mbedtls_test_cli_key_len, NULL, 0);
    if (ret != 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed !  mbedtls_pk_parse_key returned -0x%x while parsing private key", -ret);
        return NETWORK_PK_PRIVATE_KEY_PARSE_ERROR;
    }

    PRINTF("\nhttps_client_tls_init():: Connecting to %s:%s", host, service);
    char *local_host = "172.16.3.30";
    char *local_service = "8443";
    struct addrinfo hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    ret = getaddrinfo(local_host, local_service, &hints, &res);
    if ((ret != 0) || (res == NULL))
    {
        return NETWORK_ERR_NET_UNKNOWN_HOST;
    }
    PRINTF(	"\nhttps_client_tls_init():: Creating a Socket");
    tlsDataParams.fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (tlsDataParams.fd < 0)
    {
        return NETWORK_ERR_NET_SOCKET_FAILED;
    }
    PRINTF("\nhttps_client_tls_init()::  Connecting to the socket");
    ret = connect(tlsDataParams.fd, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);

    if (ret != 0)
    {
        PRINTF("\nhttps_client_tls_init()::Connect failed: %s", strerror(errno));
        close(tlsDataParams.fd);
        return NETWORK_ERR_NET_CONNECT_FAILED;
    }

    PRINTF("\nhttps_client_tls_init():: Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&(tlsDataParams.conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed  ! mbedtls_ssl_config_defaults returned -0x%x", -ret);
        return SSL_CONNECTION_ERROR;
    }
    PRINTF("\nhttps_client_tls_init():: ok");

    /* mbedtls_ssl_conf_verify(&(tlsDataParams.conf), _iot_tls_verify_cert, NULL); */

    if (ServerVerificationFlag == true)
    {
        mbedtls_ssl_conf_authmode(&(tlsDataParams.conf), MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    else
    {
        mbedtls_ssl_conf_authmode(&(tlsDataParams.conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    mbedtls_ssl_conf_rng(&(tlsDataParams.conf), mbedtls_hmac_drbg_random, &(tlsDataParams.hmac_drbg));

    mbedtls_ssl_conf_ca_chain(&(tlsDataParams.conf), &(tlsDataParams.cacert), NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams.conf), &(tlsDataParams.clicert), &(tlsDataParams.pkey))) != 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed  ! mbedtls_ssl_conf_own_cert returned %d ", ret);
        return SSL_CONNECTION_ERROR;
    }

    if ((ret = mbedtls_ssl_setup(&(tlsDataParams.ssl), &(tlsDataParams.conf))) != 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed  ! mbedtls_ssl_setup returned -0x%x", -ret);
        return SSL_CONNECTION_ERROR;
    }
    if ((ret = mbedtls_ssl_set_hostname(&(tlsDataParams.ssl), local_host)) != 0)
    {
        PRINTF("\nhttps_client_tls_init():: failed ! mbedtls_ssl_set_hostname returned %d", ret);
        return SSL_CONNECTION_ERROR;
    }

    mbedtls_ssl_set_bio(&(tlsDataParams.ssl), &(tlsDataParams.fd), lwipSend, (mbedtls_ssl_recv_t *)lwipRecv, NULL);

    PRINTF("\nhttps_client_tls_init():: SSL state connect : %d ", tlsDataParams.ssl.state);
    PRINTF("\nhttps_client_tls_init():: Performing the SSL/TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&(tlsDataParams.ssl))) != 0)
    {
    	char error_buf[100];
		mbedtls_strerror(ret, error_buf, sizeof(error_buf));
		PRINTF("\nHTTPS CLIENT::https_client_tls_init()::mbedtls_ssl_handshake failed: %s", error_buf);
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            PRINTF("\nhttps_client_tls_init()::failed  ! mbedtls_ssl_handshake returned -0x%x", -ret);
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
            {
                PRINTF(
                    "\nhttps_client_tls_init()::    Unable to verify the server's certificate. "
                    "    Alternatively, you may want to use "
                    "auth_mode=optional for testing purposes.");
            }
            return SSL_CONNECTION_ERROR;
        }
    }

    PRINTF(" \nhttps_client_tls_init()::   [ Protocol is %s ]    [ Ciphersuite is %s ]", mbedtls_ssl_get_version(&(tlsDataParams.ssl)),
           mbedtls_ssl_get_ciphersuite(&(tlsDataParams.ssl)));
    if ((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams.ssl))) >= 0)
    {
        PRINTF("\nhttps_client_tls_init():: [ Record expansion is %d ]\n", ret);
    }
    else
    {
        PRINTF("\nhttps_client_tls_init():: [ Record expansion is unknown (compression) ]");
    }

    PRINTF("\nhttps_client_tls_init()::  Verifying peer X.509 certificate...");

    if (ServerVerificationFlag == true)
    {
        if ((tlsDataParams.flags = mbedtls_ssl_get_verify_result(&(tlsDataParams.ssl))) != 0)
        {
            PRINTF("\nhttps_client_tls_init():: FAILED");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", tlsDataParams.flags);
            PRINTF("%s\n", vrfy_buf);
            ret = SSL_CONNECTION_ERROR;
        }
        else
        {
            PRINTF("OK");
            ret = SUCCESS;
        }
    }
    else
    {
        PRINTF("SKIPPED");
        ret = SUCCESS;
    }

#ifdef PRINT_CERT_INFO
    if (mbedtls_ssl_get_peer_cert(&(tlsDataParams.ssl)) != NULL)
    {
        PRINTF("  . Peer certificate information    ...\n");
        mbedtls_x509_crt_info((char *)buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams.ssl)));
        PRINTF("%s\n", buf);
    }
#endif

    return (Error_t)ret;
}


/* Release TLS */
void https_client_tls_release(void)
{
    lwip_close(tlsDataParams.fd);
    mbedtls_x509_crt_free(&(tlsDataParams.clicert));
    mbedtls_x509_crt_free(&(tlsDataParams.cacert));
    mbedtls_pk_free(&(tlsDataParams.pkey));
    mbedtls_ssl_free(&(tlsDataParams.ssl));
    mbedtls_ssl_config_free(&(tlsDataParams.conf));
    mbedtls_hmac_drbg_free(&(tlsDataParams.hmac_drbg));
    mbedtls_entropy_free(&(tlsDataParams.entropy));
}

int OtaHttp_DeviceProvision(const char *host)//, SemaphoreHandle_t xSemaphore)
{
    int ret = EXIT_FAILURE; // Default to failure

    // Lock semaphore
    PRINTF("Attempting to take semaphore...\n");
    //xSemaphoreTake(xSemaphore, portMAX_DELAY);
    PRINTF("Semaphore taken.\n");
    
    PRINTF("Starting device provisioning...\n");

    NetworkContext_t coreHttp_NetCtx = {&tlsDataParams.ssl};
    TransportInterface_t ti = {.recv = coreHttp_recv, .send = coreHttp_send, .pNetworkContext = &coreHttp_NetCtx};
    struct OtaHttpConf httpConf = {.ti = &ti, .dataBuf = https_buf, .dataBufSize = sizeof(https_buf), .hostName = host};
    PRINTF("Provisioning device in Hawkbit Server, Host: %s\n", host);

    // Verify if server is up
    PRINTF("Verifying if server is up...\n");
    ret = OtaHttp_VerifyServerUp(&httpConf);
    if (ret != HTTPSuccess)
    {
        PRINTF("Server is not up, exiting...\n");
        return -HTTPInvalidResponse;
    }

    // Enable target token authentication
    PRINTF("Enabling target token authentication...\n");
    ret = OtaHttp_EnableTargetTokenAuth(&httpConf);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to enable target token authentication, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }

    // Perform device pre-provision
    PRINTF("Performing device pre-provision...\n");
    HTTPRequestInfo_t request;
    HTTPRequestHeaders_t requestHeaders;
    HTTPResponse_t response;
    const char *fPath = "/rest/v1/targets";
    ret = OtaHttp_PostDevicePreProvisionRequest(&httpConf);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to pre-provision device, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }

    // Register the device
    PRINTF("Registering the device...\n");
    ret = OtaHttp_GetDeviceConfig(&httpConf);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to register device, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }
    PRINTF("Updating Device Config...\n");
    ret = OtaHttp_UpdateDeviceConfig(&httpConf);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to update device config, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }

    PRINTF("Polling for Updates\n");
    ret = OtaHttp_GetDeviceConfig(&httpConf);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to find Updates for the  device, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }
    PRINTF("Inspecting Deployment Action\n");
    ret = OtaHttp_InspectDeploymentAction(&httpConf);
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to inspect deployment action, ret=%d\n", ret);
        return -HTTPInvalidResponse;
    }
    PRINTF("Device Provisioning Completed\n");
    // Unlock semaphore
    //xSemaphoreGive(xSemaphore);

    return ret;
   
}

int https_client_ota_download(const char *host, const char *fPath, uint32_t dstAddrPhy, size_t dstSize, size_t *fSize)
{
    NetworkContext_t coreHttp_NetCtx = {&tlsDataParams.ssl};
    TransportInterface_t ti = {.recv = coreHttp_recv, .send = coreHttp_send, .pNetworkContext = &coreHttp_NetCtx};
    struct OtaHttpConf httpConf = {.ti = &ti, .dataBuf = https_buf, .dataBufSize = sizeof(https_buf), .hostName = host};
    int ret;
    unsigned char md_net[32], md_flash[32];
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts_ret(&sha256_ctx, 0);
    uint32_t addr_phy   = dstAddrPhy;
    uint32_t file_size  = 0;
    size_t storage_size = dstSize;
    PRINTF("\nGetting size of requested file '%s'\n", fPath);
    file_size = OtaHttp_GetFileSize();
    if (ret != HTTPSuccess)
    {
        PRINTF("Failed to get file size, ret=%d\n", ret);
        return EXIT_FAILURE;
    }
    PRINTF("Determined file size is %u bytes\n", file_size);
    if (file_size > storage_size)
    {
        PRINTF("Requested file TOO BIG! file_size=%d storage_size=%d\n", file_size, storage_size);
        return EXIT_FAILURE;
    }
    PRINTF("Starting download of %u bytes with block size of %u bytes\n", file_size, OTA_HTTP_BLOCK_SIZE);
    /* Read the file in chunks from the downloaded file */
    uint32_t bytes_recvd = 0;
    while (bytes_recvd < file_size)
    {
        size_t flash_offset = addr_phy + bytes_recvd;
        status_t status;
        size_t remains      = file_size - bytes_recvd;
        size_t chunk        = (remains < OTA_HTTP_BLOCK_SIZE) ? remains : OTA_HTTP_BLOCK_SIZE;
        int cnt;
        /* Read the chunk from the downloaded file */
        cnt = OtaHttp_DownloadArtifact(&httpConf, bytes_recvd, chunk, https_buf);

        PUTCHAR('.');
        if (cnt < 0)
        {
            PRINTF("\nHTTPS CLIENT::https_client_ota_download()::HTTP File Request at offset %u failed with %d", bytes_recvd, cnt);
            break;
        }
        if (cnt != chunk)
        {
            PRINTF("UNEXPECTED size read at offset %u: %u read, %u expected.\n", bytes_recvd, cnt, chunk);
            break;
        }
        mbedtls_sha256_update(&sha256_ctx, https_buf, cnt);
        /* Flash erase is done on the fly with download since erasing large portion
        * of flash while executing from it would cause other system tasks to starve
        * (e.g. TCP connection)
        */
        if (0 == (flash_offset % MFLASH_SECTOR_SIZE))
        {
            status = mflash_drv_sector_erase(flash_offset);
            if (status != kStatus_Success)
            {
                PRINTF("FAILED to erase sector at offset %u\n", addr_phy);
                break;
            }
        }
        PRINTF("\nHTTPS CLIENT::https_client_ota_download()::Data before writing to flash:");
        for (size_t i = 0; i < cnt; i++) {
            PRINTF("%02x", https_buf[i]);
        }
        PRINTF("\n");
        flash_program(flash_offset, https_buf, cnt);
        bytes_recvd += cnt;
    }
    PRINTF("\nDownload loop completed with size %u, expected %u\n\n", bytes_recvd, file_size);
    if (bytes_recvd != file_size)
    {
        PRINTF("FAILED to download requested file.\n");
        return EXIT_FAILURE;
    }
    // Message Digest check
    mbedtls_sha256_finish(&sha256_ctx, md_net);
    flash_sha256(addr_phy, file_size, md_flash);
    if (memcmp(md_net, md_flash, sizeof(md_flash)) != 0)
    {
        PRINTF("FAILED to compare MD.\n");
        return EXIT_FAILURE;
    }
    if (fSize)
    {
        *fSize = file_size;
    }
    return SUCCESS;
}

int https_client_sendFeedback(char *host, int status)
{
    int ret;

    NetworkContext_t coreHttp_NetCtx = {&tlsDataParams.ssl};

    TransportInterface_t ti = {.recv = coreHttp_recv, .send = coreHttp_send, .pNetworkContext = &coreHttp_NetCtx};

    struct OtaHttpConf httpConf = {.ti = &ti, .dataBuf = https_buf, .dataBufSize = sizeof(https_buf), .hostName = host};
 
    ret = OtaHttp_SendFeedback(&httpConf, status);
    return ret;

}

