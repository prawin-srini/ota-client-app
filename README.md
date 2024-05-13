SDK version
===========
- Version: 2.15.000

MCUXpresso IDE version 
===========
- Version: 11.9.0

Hardware requirements
=====================
- Mini/micro USB cable
- Ethernet cable
- EVK-MIMXRT1060 board

PreRequisites
=====================
- Hawkbit server version 0.4 running. Code availble at https://github.com/prawin-srini/hawkbit/tree/Hawkbit-changes
- mcuboot-opensource SBL from the SDK Management


iMXRT1060 OTA Client Application for the Hawkbit Server
Steps to run the client.
1. Configure the project using the settings found in porject_config.xml
2. Use the mcuboot-opensource as the Secondary Bootloader in Flash at address 0x60000000
3. Sign the application and candidate image using imgtool sign --key sign-rsa2048-priv.pem
	      --align 4
	      --header-size 0x400
	      --pad-header
	      --slot-size 0x200000
	      --max-sectors 800
	      --version "1.0.0-0"
	      app_binary.bin
	      app_binary_SIGNED.bin 
4. Run the SBL and flash the signed client application at 0x60040000
5. Ensure that the hawkbit server is up and running
6. Create a software module for the device in the hawkbit managment dashboard that is mapped to the device and track the update via UART or the server.
7. Client downloads the new image, restarts with the new image

Further information for the application can be referrred from the example SDK project for the iMXRT1060 from NXP in the XpressoIDE or at https://github.com/nxp-mcuxpresso/mcux-sdk-examples/tree/main/evkmimxrt1060/ota_examples
