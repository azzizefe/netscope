# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors
Configuration NetscopeAgentDSC {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerUrl,
        [Parameter(Mandatory=$true)]
        [string]$EnrollmentToken,
        [string]$SensorGroup = "Default"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node "localhost" {
        Package InstallNetscopeAgent {
            Ensure = "Present"
            Name = "Netscope Enterprise Agent"
            Path = "C:\Installers\netscope-agent-0.2.0-x64.msi"
            ProductId = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
            Arguments = "/qn /norestart NETSCOPE_SERVER_URL=`"$ServerUrl`" NETSCOPE_ENROLLMENT_TOKEN=`"$EnrollmentToken`" NETSCOPE_SENSOR_GROUP=`"$SensorGroup`""
        }

        Service NetscopeService {
            Name = "NetscopeAgent"
            StartupType = "Automatic"
            State = "Running"
            DependsOn = "[Package]InstallNetscopeAgent"
        }
    }
}
