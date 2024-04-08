
### [Unified sensor](#unified-sensor)

If you're using a unified Microsoft Defender for Endpoint and Defender for Identity sensor, supported operating systems include:

- Windows Server 2019
- Window Server 2022
- [Patch level March 2024 Cumulative Update](https://support.microsoft.com/topic/march-12-2024-kb5035857-os-build-20348-2340-a7953024-bae2-4b1a-8fc1-74a17c68203c)

> [!IMPORTANT]
> After installing Patch level March 2024 Cumulative Update, LSASS might experience a memory leak on domain controllers when on-premises and cloud-based Active Directory Domain Controllers service Kerberos authentication requests.
>
> This issue is addressed in the out-of-band update KB5037422.

---






If you're using a unified Microsoft Defender for Endpoint and Defender for Identity sensor, the sensor uses Microsoft Defender for Endpoint URL endpoints for communication. The unified sensor supports simplified URLs.

For more information, see [Configure your network environment to ensure connectivity with Defender for Endpoint](/microsoft-365/security/defender-endpoint/configure-environment##enable-access-to-microsoft-defender-for-endpoint-service-urls-in-the-proxy-server).
