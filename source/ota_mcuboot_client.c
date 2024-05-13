/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2020 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <stdio.h>
#include <ctype.h>

#include "httpsclient.h"
#include "pin_mux.h"
#include "board.h"
#include "lwip/netifapi.h"
#include "lwip/opt.h"
#include "lwip/tcpip.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
#include "mflash_drv.h"
#include "fsl_debug_console.h"
#include "ota_config.h"
#include "network_cfg.h"
//#include "fsl_shell.h"
#include "sysflash/sysflash.h"
#include "flash_map.h"
#include "mcuboot_app_support.h"
#include "semphr.h"
#include "hawkbit_config.h"

#ifdef WIFI_MODE
#include "wpl.h"
#endif

#include "fsl_iomuxc.h"
#include "fsl_enet.h"
#include "fsl_phyksz8081.h"
#include "ksdk_mbedtls.h"
//#include "fsl_gpt.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* @TEST_ANCHOR */

/* Ethernet configuration. */
extern phy_ksz8081_resource_t g_phy_resource;
#define EXAMPLE_ENET         ENET
#define EXAMPLE_PHY_ADDRESS  BOARD_ENET0_PHY_ADDRESS
#define EXAMPLE_PHY_OPS      &phyksz8081_ops
#define EXAMPLE_PHY_RESOURCE &g_phy_resource
#define EXAMPLE_CLOCK_FREQ   CLOCK_GetFreq(kCLOCK_IpgClk)
#define OTA_TASK_PRIORITY (2U)
//SemaphoreHandle_t xSemaphore = NULL;
static SemaphoreHandle_t ota_semaphore;
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
//volatile uint32_t McuRTOS_RunTimeCounter = 0;
int initNetwork(void);

//static shell_status_t shellCmd_ota(shell_handle_t shellHandle, int32_t argc, char **argv);
//static shell_status_t shellCmd_image(shell_handle_t shellHandle, int32_t argc, char **argv);
//static shell_status_t shellCmd_reboot(shell_handle_t shellHandle, int32_t argc, char **argv);
//static shell_status_t shellCmd_provision(shell_handle_t shellHandle, int32_t argc, char **argv);

#ifdef WIFI_MODE
static shell_status_t shellCmd_wifi(shell_handle_t shellHandle, int32_t argc, char **argv);
#endif

/*******************************************************************************
 * Variables
 ******************************************************************************/
phy_ksz8081_resource_t g_phy_resource;

//static SHELL_COMMAND_DEFINE(ota,
//                            "\n\"ota <imageNumber> <filePath> <host> <port>\": Starts download of OTA image\n",
//                            shellCmd_ota,
//                            SHELL_IGNORE_PARAMETER_COUNT);
//
//static SHELL_COMMAND_DEFINE(image,
//                            "\n\"image [info]\"              : Print image information"
//                            "\n\"image test <imageNumber>\"  : Mark secondary image of given number as ready for test"
//                            "\n\"image accept <imageNumber>\": Mark primary image of given number as accepted"
//                            "\n",
//                            shellCmd_image,
//                            SHELL_IGNORE_PARAMETER_COUNT);
//
//static SHELL_COMMAND_DEFINE(reboot, "\n\"reboot\": Triggers software reset\n", shellCmd_reboot, 0);
////static SHELL_COMMAND_DEFINE(provision, "\n\"provision\": Provision the device\n", shellCmd_provision, 0);
//#ifdef WIFI_MODE
//static SHELL_COMMAND_DEFINE(wifi,
//                            "\n\"wifi conf [ssid pass]\" : Get/Set WiFi SSID and passphrase"
//                            "\n\"wifi join\"             : Connect to network"
//                            "\n\"wifi leave\"            : Disconnect from network"
//                            "\n",
//                            shellCmd_wifi,
//                            SHELL_IGNORE_PARAMETER_COUNT);
//
//static char wifi_ssid[32 + 1] = WIFI_SSID;
//static char wifi_pass[64 + 1] = WIFI_PASSWORD;
//#endif
//
//SDK_ALIGN(static uint8_t s_shellHandleBuffer[SHELL_HANDLE_SIZE], 4);
//static shell_handle_t s_shellHandle;

/*******************************************************************************
 * Code
 ******************************************************************************/
void BOARD_InitModuleClock(void)
{
    const clock_enet_pll_config_t config = {.enableClkOutput = true, .enableClkOutput25M = false, .loopDivider = 1};
    CLOCK_InitEnetPll(&config);
}

static void MDIO_Init(void)
{
    (void)CLOCK_EnableClock(s_enetClock[ENET_GetInstance(EXAMPLE_ENET)]);
    ENET_SetSMI(EXAMPLE_ENET, EXAMPLE_CLOCK_FREQ, false);
}

static status_t MDIO_Write(uint8_t phyAddr, uint8_t regAddr, uint16_t data)
{
    return ENET_MDIOWrite(EXAMPLE_ENET, phyAddr, regAddr, data);
}

static status_t MDIO_Read(uint8_t phyAddr, uint8_t regAddr, uint16_t *pData)
{
    return ENET_MDIORead(EXAMPLE_ENET, phyAddr, regAddr, pData);
}

static void print_image_info(void)
{
    for (int image = 0; image < MCUBOOT_IMAGE_NUMBER; image++)
    {
        status_t status;
        uint32_t imgstate;
        const char *name = boot_image_names[image];

        status = bl_get_image_state(image, &imgstate);
        if (status != kStatus_Success)
        {
            PRINTF("\nOTA MCUBOOT CLIENT::print_image_info()::Failed to get state of image %u (ret %d)", image, status);
            return;
        }

        PRINTF("\nOTA MCUBOOT CLIENT::print_image_info()::Image %d; name %s; state %s:", image, name, bl_imgstate_to_str(imgstate));

        for (int slot = 0; slot < 2; slot++)
        {
            int faid              = image * 2 + slot;
            struct flash_area *fa = &boot_flash_map[faid];
            uint32_t slotaddr     = fa->fa_off + BOOT_FLASH_BASE;
            uint32_t slotsize     = fa->fa_size;
            static struct image_header ih;

            status = mflash_drv_read(fa->fa_off, (uint32_t *)&ih, sizeof(ih));
            if (status != kStatus_Success)
            {
                PRINTF("\nOTA MCUBOOT CLIENT::print_image_info()::Failed to read image header");
                return;
            }
            int slotused = ih.ih_magic == IMAGE_MAGIC;

            PRINTF("\nOTA MCUBOOT CLIENT::print_image_info()::  Slot %d; slotAddr %x; slotSize %u", faid, slotaddr, slotsize);

            if (slotused)
            {
                struct image_version *iv = &ih.ih_ver;
                char versionstr[40];

                snprintf(versionstr, sizeof(versionstr), "%u.%u.%u.%lu", iv->iv_major, iv->iv_minor, iv->iv_revision,
                         iv->iv_build_num);

                PRINTF("\nOTA MCUBOOT CLIENT::print_image_info():: <IMAGE %s: size %u; version %s>", fa->fa_name, ih.ih_img_size, versionstr);
            }
            else
            {
                PRINTF("\nOTA MCUBOOT CLIENT::print_image_info():: <EMPTY>");
            }
        }
    }
}

#ifdef WIFI_MODE
static shell_status_t shellCmd_wifi(shell_handle_t shellHandle, int32_t argc, char **argv)
{
    const char *action   = argv[1];
    static int connected = 0;

    if (argc > 4)
    {
        PRINTF("OTA MCUBOOT CLIENT::Too many arguments.\n");
        return kStatus_SHELL_Error;
    }

    /* wifi conf [ssid password] */

    if (!strcmp(action, "conf"))
    {
        /* SSID */
        if (argc > 2)
        {
            const char *ssid = argv[2];

            if (strlen(ssid) > sizeof(wifi_ssid) - 1)
            {
                PRINTF("OTA MCUBOOT CLIENT::SSID too long (max %d)\n", sizeof(wifi_ssid) - 1);
                return kStatus_SHELL_Error;
            }
            strcpy(wifi_ssid, ssid);
        }

        /* Password */
        if (argc > 3)
        {
            const char *pass = argv[3];

            if (strlen(pass) > sizeof(wifi_pass) - 1)
            {
                PRINTF("OTA MCUBOOT CLIENT::Passphrase too long (max %d)\n", sizeof(wifi_pass) - 1);
                return kStatus_SHELL_Error;
            }
            strcpy(wifi_pass, pass);
        }

        PRINTF("OTA MCUBOOT CLIENT::SSID \"%s\"; Passphrase \"%s\"\n", wifi_ssid, wifi_pass);
    }

    /* wifi join */

    else if (!strcmp(action, "join"))
    {
        int result;

        if (connected)
        {
            PRINTF("OTA MCUBOOT CLIENT::Already connected\n");
            return kStatus_SHELL_Success;
        }

        result = WPL_AddNetwork(wifi_ssid, wifi_pass, "ota");
        if (result != WPLRET_SUCCESS)
        {
            PRINTF("OTA MCUBOOT CLIENT::Failed to create wifi network descriptor (%d)\n", result);
            return kStatus_SHELL_Error;
        }

        PRINTF("OTA MCUBOOT CLIENT::Joining: \"%s\"\n", wifi_ssid);

        result = WPL_Join("ota");
        if (result != WPLRET_SUCCESS)
        {
            PRINTF("OTA MCUBOOT CLIENT::Failed to join WiFi network.\n");
            WPL_RemoveNetwork("ota");
            return kStatus_SHELL_Error;
        }

        PRINTF("OTA MCUBOOT CLIENT::Successfully joined: \"%s\"\n", wifi_ssid);

        char ip[16];
        WPL_GetIP(ip, 1);

        PRINTF("OTA MCUBOOT CLIENT::Got IP address %s\n", ip);

        connected = 1;
    }

    /* wifi leave */

    else if (!strcmp(action, "leave"))
    {
        if (!connected)
        {
            PRINTF("OTA MCUBOOT CLIENT::No connection\n");
            return kStatus_SHELL_Success;
        }

        WPL_Leave();
        WPL_RemoveNetwork("ota");

        connected = 0;
    }

    else
    {
        PRINTF("OTA MCUBOOT CLIENT::Wrong arguments. See 'help'\n");
        return kStatus_SHELL_Error;
    }

    return kStatus_SHELL_Success;
}
#endif

static int performOTA(void)
{
    int ret, image = 0; // Default image number
    size_t image_size;
    partition_t storage;

    /* Initialized with default values */
    char *path = OTA_IMAGE_PATH_DEFAULT;
    char *host = OTA_SERVER_NAME_DEFAULT;
    char *port = OTA_SERVER_PORT_DEFAULT;

    if (image < 0 || image >= MCUBOOT_IMAGE_NUMBER)
    {
        PRINTF("OTA MCUBOOT CLIENT::performOTA()::Image number out of range.\n");
        return FAILURE;
    }

    if (bl_get_update_partition_info(image, &storage) != SUCCESS)
    {
        PRINTF("OTA MCUBOOT CLIENT::performOTA()::FAILED to determine address for download\n");
        return FAILURE;
    }

    PRINTF(
        "Started OTA with:\n"
        "    image = %d\n"
        "    file = %s\n"
        "    host = %s\n"
        "    port = %s\n",
        image, path, host, port);

    /* File Download Over TLS */
    char server_path[256];
    snprintf(server_path, sizeof(server_path), "%s%s", host, path);
    ret = https_client_tls_init(server_path, port);
    if (ret != SUCCESS)
    {
        PRINTF("\nOTA MCUBOOT CLIENT::performOTA()::FAILED to init TLS (ret=%d)", ret);
        goto cleanup;
    }
    PRINTF("OTA MCUBOOT CLIENT::performOTA():: Provisioning device...\n");
    delay_ms(500);
    ret = OtaHttp_DeviceProvision(server_path); //xSemaphore);
    if(ret!=0)
    {
        PRINTF("Provisioning Failed\n");
        goto cleanup;
    }
    PRINTF(" OTA MCUBOOT CLIENT::performOTA():: Provisioning successful\n");
    delay_ms(500);
    ret = https_client_ota_download(host, path, storage.start, storage.size, &image_size);
    if (ret != SUCCESS)
    {
        PRINTF("\nOTA MCUBOOT CLIENT::performOTA()::FAILED to download OTA image (ret=%d)", ret);
        goto cleanup;
    }
    PRINTF("\nOTA MCUBOOT CLIENT::performOTA()::OTA Download Success");
    ret = https_client_sendFeedback(host, ret);
    if(ret != SUCCESS)
    {
        PRINTF("Failed to send feedback, ret=%d\n", ret);
        goto cleanup;
    }
    PRINTF("\nOTA MCUBOOT CLIENT::performOTA()::Feedback Sent Successfully");
    if (!bl_verify_image(storage.start, image_size))
    {
        PRINTF("\nOTA MCUBOOT CLIENT::performOTA()::FAILED to verify mcuboot image format");
        goto cleanup;
    }

    PRINTF("\nOTA MCUBOOT CLIENT::performOTA()::Flash Read Success");
    xSemaphoreGive(ota_semaphore);
    return SUCCESS;

cleanup:
    https_client_tls_release();
    return FAILURE;
    //return kStatus_SHELL_Success;
}

static int invokeBootLoaderImageCheck(void)
{
    int image = 0; // Default image number
    status_t status;
    uint32_t imgstate;

    print_image_info();
    PRINTF("\nOTA MCUBOOT CLIENT::invokeBootLoaderImageCheck()::Checking image %d", image); // Default image number
    if (image < 0 || image >= MCUBOOT_IMAGE_NUMBER)
    {
        PRINTF("\nOTA MCUBOOT CLIENT::invokeBootLoaderImageCheck()::Image number out of range.");
        return FAILURE;
    }

    status = bl_get_image_state(image, &imgstate);
    if (status != SUCCESS)
    {
        PRINTF("\nOTA MCUBOOT CLIENT::invokeBootLoaderImageCheck()::Failed to get state of image %u (status %d)", image, status);
        return FAILURE;
    }

    /* image test <imageNumber> */
    status = bl_update_image_state(image, kSwapType_ReadyForTest);
    if (status != SUCCESS)
    {
        PRINTF("\nOTA MCUBOOT CLIENT::invokeBootLoaderImageCheck()::FAILED to mark image state as ReadyForTest (status=%d)", status);
        return FAILURE;
    }
    
    if(imgstate != kSwapType_Testing)
    {
    	PRINTF("\nOTA MCUBOOT CLIENT::invokeBootLoaderImageCheck()::Image state is not Testing");
    	
    }
    return SUCCESS;
}

static int invokeReboot(void)
{
    PRINTF("\nOTA MCUBOOT CLIENT::invokeReboot()::System reset!");
    NVIC_SystemReset();

    /* return kStatus_SHELL_Success; */
}


static void ota_task(void *arg)
{
    int ret;
    //s_shellHandle = &s_shellHandleBuffer[0];
    int ota_status, update_status, reboot_status;
    const char *phy =
#ifdef WIFI_MODE
        "WiFi";
#else
        "Ethernet";
#endif

    PRINTF("\nOTA MCUBOOT CLIENT::ota_task()::OTA HTTPS client demo (%s)", phy);

    /* network init */
    //stats_display();
    ret = initNetwork();
    if (ret)
    {
        PRINTF("\nOTA MCUBOOT CLIENT::ota_task()::FAILED to init network (ret=%d). Reboot the board and try again.\n", ret);
        goto failed_init;
    }
    stats_display();
    /* Create the semaphore */
    ota_semaphore = xSemaphoreCreateBinary();
    if (ota_semaphore == NULL)
    {
        PRINTF("\nOTA MCUBOOT CLIENT::ota_task()::Failed to create semaphore.\n");
        goto failed_init;
    }
    //stats_display();
    /* Perform OTA */
    ota_status = performOTA();

    /* Wait for the semaphore to be given */
    if (xSemaphoreTake(ota_semaphore, portMAX_DELAY) == pdTRUE)
   {
        if(ota_status == SUCCESS)
        {
            update_status = invokeBootLoaderImageCheck();
        }
        else
        {
            PRINTF("\nOTA MCUBOOT CLIENT::ota_task()::The OTA Task exited abruptly");
            goto failed_init;
        }
    }
    stats_display();
    if(update_status == SUCCESS)
    {
        invokeReboot();
    }
    else
    {
        PRINTF("\nOTA MCUBOOT CLIENT::ota_task()::THe Image Update Task exited abruptly");
        goto failed_init;
    }

failed_init:
    vTaskDelete(NULL);
}

/*void vConfigureTimerForRunTimeStats( void )
{
    // Set the SysTick frequency to the core clock frequency
    SYST_RVR = (configCPU_CLOCK_HZ / configTICK_RATE_HZ) - 1UL;

    // Reset the SysTick counter value
    SYST_CVR = 0UL;

    // Set the SysTick to use the processor clock, and enable it
    SYST_CSR = (1 << 2) | 1;
}*/

/*
void vConfigureTimerForRunTimeStats(void) {
  uint32_t gptFreq;
  gpt_config_t gptConfig;

  GPT_GetDefaultConfig(&gptConfig);


  GPT_Init(GPT2, &gptConfig);

  GPT_SetClockDivider(GPT2, 3);

 
  gptFreq = CLOCK_GetFreq(kCLOCK_PerClk);

  gptFreq /= 3;

  gptFreq = USEC_TO_COUNT(100, gptFreq);
  GPT_SetOutputCompareValue(GPT2, kGPT_OutputCompare_Channel1, gptFreq);


  GPT_EnableInterrupts(GPT2, kGPT_OutputCompare1InterruptEnable);

  /// Enable at the Interrupt and start timer 
  EnableIRQ(GPT2_IRQn);
  GPT_StartTimer(GPT2);
}

void GPT2_IRQHandler(void) {
  // Clear interrupt flag.
  GPT_ClearStatusFlags(GPT2, kGPT_OutputCompare1Flag);
  McuRTOS_RunTimeCounter++; 
#if defined __CORTEX_M && (__CORTEX_M == 4U || __CORTEX_M == 7U)
  __DSB();
#endif
}

//Get GPT counter value
uint32_t ulGetRuntimeCounterValueFromISR(void)
{
    return McuRTOS_RunTimeCounter;//return GPT_GetCurrentTimerCount(GPT2);
}*/

/*void vApplicationStackOverflowHook( TaskHandle_t xTask, char *pcTaskName )
{
    PRINTF("Error: stack overflow in task %s\n", pcTaskName);

    // Enter an infinite loop.
    for(;;);
}*/

/*!
 * @brief Main function.
 */

void delay_ms(uint32_t delayTime) {
    SysTick->LOAD = (SystemCoreClock / 1000 - 1) * delayTime;
    SysTick->VAL = 0;
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk |
                    SysTick_CTRL_ENABLE_Msk;

    // Wait until the SysTick timer expires
    while ((SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) == 0);

    SysTick->CTRL = 0;
}


int main(void)
{
    gpio_pin_config_t gpio_config = {kGPIO_DigitalOutput, 0, kGPIO_NoIntmode};

    BOARD_ConfigMPU();
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();
    BOARD_InitModuleClock();

    IOMUXC_EnableMode(IOMUXC_GPR, kIOMUXC_GPR_ENET1TxClkOutputDir, true);

    GPIO_PinInit(GPIO1, 9, &gpio_config);
    GPIO_PinInit(GPIO1, 10, &gpio_config);
    /* Pull up the ENET_INT before RESET. */
    GPIO_WritePinOutput(GPIO1, 10, 1);
    GPIO_WritePinOutput(GPIO1, 9, 0);
    SDK_DelayAtLeastUs(10000, CLOCK_GetFreq(kCLOCK_CpuClk));
    GPIO_WritePinOutput(GPIO1, 9, 1);

    MDIO_Init();
    g_phy_resource.read  = MDIO_Read;
    g_phy_resource.write = MDIO_Write;
    CRYPTO_InitHardware();

    mflash_drv_init();

    /* start the shell */

    if (xTaskCreate(ota_task, "ota_task", 2048 /* x4 */, NULL, OTA_TASK_PRIORITY, NULL) != pdPASS)
    {
        PRINTF("OTA MCUBOOT CLIENT::main()::Task creation failed!\r\n");
        while (1)
            ;
    }
	#if !configGENERATE_RUN_TIME_STATS_USE_TICKS && configGENERATE_RUN_TIME_STATS
    	vConfigureTimerForRunTimeStats();
    /* Run RTOS */
	#endif
		vTaskStartScheduler();

    /* Should not reach this statement */
    for (;;)
        ;
}
