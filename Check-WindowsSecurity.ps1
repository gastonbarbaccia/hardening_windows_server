
# Funcion para manejar la salida de resultados
function Write-Report {
    param (
        [string]$TestName,
        [string]$Result,
        [string]$Recommendation
    )

    Write-Output "-----------------------------"
    Write-Output "Prueba: $TestName"
    Write-Output "Resultado: $Result"
    
    if ($Result -eq "FAIL") {
        Write-Output "Recomendacion: $Recommendation"
    }
    Write-Output "-----------------------------"
}

# Configuracion global para detener en errores no manejados
$ErrorActionPreference = "Stop"

# Funcion para verificar si el Firewall está habilitado
function Check-Firewall {
    try {
        $firewallStatus = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}
        if ($firewallStatus) {
            Write-Report "Firewall Habilitado" "PASS" ""
        } else {
            Write-Report "Firewall Habilitado" "FAIL" "Habilite el Firewall en todas las interfaces para proteger el sistema."
        }
    } catch {
        Write-Report "Firewall Habilitado" "FAIL" "Error al comprobar el estado del Firewall. Detalles: $_"
    }
}

# Funcion para verificar si la cuenta de Administrador está deshabilitada
function Check-AdminAccount {
    try {
        $adminAccount = Get-LocalUser -Name "Administrator"
        if ($adminAccount.Enabled -eq $false) {
            Write-Report "Cuenta Administrador" "PASS" "La cuenta de Administrador está deshabilitada."
        } else {
            Write-Report "Cuenta Administrador" "FAIL" "Deshabilite la cuenta de Administrador o cambie su nombre para reducir riesgos."
        }
    } catch {
        if ($_.Exception.Message -match "User Administrator was not found") {
            Write-Report "Cuenta Administrador" "PASS" "La cuenta de Administrador no existe."
        } else {
            Write-Report "Cuenta Administrador" "FAIL" "Error al comprobar la cuenta de Administrador. Detalles: $($_.Exception.Message)"
        }
    }
}


# Funcion para verificar si SMBv1 está habilitado
function Check-SMBv1 {
    try {
        $smbVersion = Get-WindowsFeature FS-SMB1
        if ($smbVersion.Installed) {
            Write-Report "SMBv1 Habilitado" "FAIL" "Deshabilite SMBv1 para evitar vulnerabilidades criticas como WannaCry."
        } else {
            Write-Report "SMBv1 Habilitado" "PASS" ""
        }
    } catch {
        Write-Report "SMBv1 Habilitado" "FAIL" "Error al comprobar SMBv1. Detalles: $_"
    }
}

# Funcion para verificar la politica de contrasenas
function Check-PasswordPolicy {
    try {
        # Obtener longitud mínima de contraseñas desde políticas locales
        $minLength = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength").MinimumPasswordLength

        # Obtener complejidad de contraseñas desde el registro
        $complexity = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordComplexity").PasswordComplexity

        if ($minLength -ge 8 -and $complexity -eq 1) {
            Write-Report "Politica de Contrasena" "PASS" "La política de contraseñas cumple con los requisitos."
        } else {
            Write-Report "Politica de Contrasena" "FAIL" "Establezca contraseñas de al menos 8 caracteres y habilite la complejidad."
        }
    } catch {
        Write-Report "Politica de Contrasena" "FAIL" "Error al comprobar la política de contraseñas. Detalles: $($_.Exception.Message)"
    }
}


# Funcion para verificar si el Control de Cuentas de Usuario (UAC) está habilitado
function Check-UAC {
    try {
        $uacStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
        if ($uacStatus.EnableLUA -eq 1) {
            Write-Report "Control de Cuentas de Usuario (UAC)" "PASS" ""
        } else {
            Write-Report "Control de Cuentas de Usuario (UAC)" "FAIL" "Habilite el Control de Cuentas de Usuario para prevenir cambios no autorizados."
        }
    } catch {
        Write-Report "Control de Cuentas de Usuario (UAC)" "FAIL" "Error al comprobar UAC. Detalles: $_"
    }
}

# Funcion para verificar si el Escritorio Remoto (RDP) está habilitado
function Check-RDP {
    try {
        $rdpStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        if ($rdpStatus.fDenyTSConnections -eq 1) {
            Write-Report "Escritorio Remoto (RDP)" "PASS" ""
        } else {
            Write-Report "Escritorio Remoto (RDP)" "FAIL" "Deshabilite RDP si no es necesario o use medidas adicionales como RDP Gateway."
        }
    } catch {
        Write-Report "Escritorio Remoto (RDP)" "FAIL" "Error al comprobar RDP. Detalles: $_"
    }
}

# Funcion para verificar si BitLocker está habilitado en las unidades del sistema
function Check-BitLocker {
    try {
        # Comprobar si el módulo de BitLocker está disponible
        if (-not (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            Write-Report "BitLocker en Unidades del Sistema" "FAIL" "El módulo de BitLocker no está disponible. Instale la característica de BitLocker."
            return
        }

        # Obtener el estado de las unidades protegidas por BitLocker
        $bitlockerStatus = Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" }

        if ($bitlockerStatus) {
            Write-Report "BitLocker en Unidades del Sistema" "PASS" "Todas las unidades están completamente cifradas con BitLocker."
        } else {
            Write-Report "BitLocker en Unidades del Sistema" "FAIL" "Active BitLocker para cifrar las unidades y proteger los datos en caso de pérdida."
        }
    } catch {
        Write-Report "BitLocker en Unidades del Sistema" "FAIL" "Error al comprobar BitLocker. Detalles: $($_.Exception.Message)"
    }
}


# Funcion para verificar si se está usando el protocolo TLS 1.2
function Check-TLS {
    try {
        # Comprobar si la clave de registro para TLS 1.2 existe
        $tls12Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
        if (-not (Test-Path -Path $tls12Path)) {
            Write-Report "Protocolo TLS 1.2" "FAIL" "La configuración de TLS 1.2 no existe. Verifique y configure las claves de registro necesarias."
            return
        }

        # Obtener el valor "Enabled" de la configuración de TLS 1.2
        $tls12 = Get-ItemProperty -Path $tls12Path -Name "Enabled" -ErrorAction Stop

        if ($tls12.Enabled -eq 1) {
            Write-Report "Protocolo TLS 1.2" "PASS" "TLS 1.2 está habilitado en el servidor."
        } else {
            Write-Report "Protocolo TLS 1.2" "FAIL" "TLS 1.2 no está habilitado. Habilítelo y deshabilite versiones anteriores como TLS 1.0 y SSL."
        }
    } catch {
        Write-Report "Protocolo TLS 1.2" "FAIL" "Error al comprobar TLS 1.2. Detalles: $($_.Exception.Message)"
    }
}


# Verificar si Windows Update está habilitado y configurado para actualizaciones automáticas.
function Check-WindowsUpdates {
    try {
        $updateStatus = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"
        if ($updateStatus.NoAutoUpdate -eq 0) {
            Write-Report "Actualizaciones Automaticas" "PASS" ""
        } else {
            Write-Report "Actualizaciones Automaticas" "FAIL" "Habilite las actualizaciones automáticas para garantizar la instalacion de parches criticos."
        }
    } catch {
        Write-Report "Actualizaciones Automaticas" "FAIL" "Error al comprobar el estado de Windows Update. Detalles: $_"
    }
}

# Configuracion del registro (Restricciones criticas)
function Check-LMHash {
    try {
        $lmHash = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash"
        if ($lmHash.NoLMHash -eq 1) {
            Write-Report "Almacenamiento de LM Hash" "PASS" ""
        } else {
            Write-Report "Almacenamiento de LM Hash" "FAIL" "Configure 'NoLMHash' para evitar el almacenamiento de contrasenas obsoletas y vulnerables."
        }
    } catch {
        Write-Report "Almacenamiento de LM Hash" "FAIL" "Error al comprobar LM Hash. Detalles: $_"
    }
}

# Verificar y deshabilitar servicios no esenciales.
# Servicios como Telnet, FTP, SNMP y otros que no sean estrictamente necesarios deben estar deshabilitados.
function Check-UnnecessaryServices {
    $services = @("Telnet", "SNMP", "FTP")
    foreach ($service in $services) {
        try {
            $serviceStatus = Get-Service -Name $service
            if ($serviceStatus.Status -eq "Stopped") {
                Write-Report "Servicio $service" "PASS" ""
            } else {
                Write-Report "Servicio $service" "FAIL" "Deshabilite el servicio $service para reducir superficies de ataque."
            }
        } catch {
            Write-Report "Servicio $service" "PASS" "No encontrado. (Podria estar desinstalado)"
        }
    }
}

# Auditoria de eventos
function Check-AuditPolicy {
    try {
        $auditPolicy = AuditPol /get /category:* | Where-Object { $_ -like "*Logon/Logoff*" }
        if ($auditPolicy) {
            Write-Report "Politica de Auditoria" "PASS" ""
        } else {
            Write-Report "Politica de Auditoria" "FAIL" "Configure una politica de auditoria para registrar eventos clave como inicios de sesion fallidos."
        }
    } catch {
        Write-Report "Politica de Auditoria" "FAIL" "Error al comprobar la politica de auditoria. Detalles: $_"
    }
}

# Bloqueo de dispositivos USB
function Check-USBRestrictions {
    try {
        $usbStatus = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start"
        if ($usbStatus.Start -eq 3) {
            Write-Report "Restriccion de Dispositivos USB" "PASS" ""
        } else {
            Write-Report "Restriccion de Dispositivos USB" "FAIL" "Configure 'USBSTOR' en el registro para bloquear dispositivos USB no autorizados."
        }
    } catch {
        Write-Report "Restriccion de Dispositivos USB" "FAIL" "Error al comprobar las restricciones de USB. Detalles: $_"
    }
}


# Tiempo de bloqueo de pantalla
function Check-ScreenLock {
    try {
        $screenLock = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut"
        if ($screenLock.ScreenSaveTimeOut -le 900) { # 900 segundos = 15 minutos
            Write-Report "Bloqueo Automático de Pantalla" "PASS" ""
        } else {
            Write-Report "Bloqueo Automático de Pantalla" "FAIL" "Configure el bloqueo automático de pantalla después de 15 minutos o menos."
        }
    } catch {
        Write-Report "Bloqueo Automático de Pantalla" "FAIL" "Error al comprobar el tiempo de bloqueo. Detalles: $_"
    }
}

# Configuracion de politicas locales
function Check-LoginFailures {
    try {
        $lockoutThreshold = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "LockoutBadCount"
        if ($lockoutThreshold -le 5) {
            Write-Report "Bloqueo tras Intentos Fallidos" "PASS" ""
        } else {
            Write-Report "Bloqueo tras Intentos Fallidos" "FAIL" "Configure el bloqueo automático tras 5 intentos fallidos para prevenir ataques de fuerza bruta."
        }
    } catch {
        Write-Report "Bloqueo tras Intentos Fallidos" "FAIL" "Error al comprobar el limite de intentos fallidos. Detalles: $_"
    }
}

# Validar y configurar la proteccion de scripts y macros
function Check-ExecutionPolicy {
    try {
        $executionPolicy = Get-ExecutionPolicy -Scope LocalMachine
        if ($executionPolicy -eq "Restricted" -or $executionPolicy -eq "AllSigned") {
            Write-Report "Politica de Ejecucion de Scripts (PowerShell)" "PASS" "Configuracion adecuada."
        } else {
            Write-Report "Politica de Ejecucion de Scripts (PowerShell)" "FAIL" "Configure la politica de ejecucion en 'Restricted' o 'AllSigned' para mayor seguridad."
        }
    } catch {
        Write-Report "Politica de Ejecucion de Scripts (PowerShell)" "FAIL" "Error al comprobar la politica de ejecucion. Detalles: $_"
    }
}

# Verificar usuarios con contrasenas nunca expiran
function Check-PasswordNeverExpires {
    try {
        $users = Get-LocalUser | Where-Object { $_.PasswordNeverExpires -eq $true }
        if ($users) {
            Write-Report "Cuentas con contrasenas que nunca expiran" "FAIL" "Configure politicas para evitar contrasenas que nunca expiran en las cuentas: $($users.Name -join ', ')."
        } else {
            Write-Report "Cuentas con contrasenas que nunca expiran" "PASS" ""
        }
    } catch {
        Write-Report "Cuentas con contrasenas que nunca expiran" "FAIL" "Error al comprobar contrasenas no expiran. Detalles: $_"
    }
}

# Revisar configuraciones de servicios criticos
# Algunos servicios criticos, como WMI, Remote Registry, y WSUS, deben estar habilitados o configurados adecuadamente según las necesidades del servidor.

function Check-CriticalServices {
    $services = @("WinRM", "RemoteRegistry", "wuauserv") # Agrega servicios clave aqui
    foreach ($service in $services) {
        try {
            $status = Get-Service -Name $service
            if ($status.Status -ne "Running") {
                Write-Report "Servicio critico $service" "FAIL" "El servicio $service no está corriendo. Revise la configuracion."
            } else {
                Write-Report "Servicio critico $service" "PASS" ""
            }
        } catch {
            Write-Report "Servicio critico $service" "FAIL" "Error al comprobar el servicio $service. Detalles: $_"
        }
    }
}

# Deshabilitar cuentas inactivas
function Check-InactiveAccounts {
    try {
        $threshold = (Get-Date).AddDays(-30) # Cuentas inactivas por más de 30 dias
        $inactiveUsers = Get-LocalUser | Where-Object { $_.LastLogon -lt $threshold }
        if ($inactiveUsers) {
            Write-Report "Cuentas inactivas" "FAIL" "Deshabilite o elimine las siguientes cuentas inactivas: $($inactiveUsers.Name -join ', ')."
        } else {
            Write-Report "Cuentas inactivas" "PASS" ""
        }
    } catch {
        Write-Report "Cuentas inactivas" "FAIL" "Error al comprobar cuentas inactivas. Detalles: $_"
    }
}

# Configuracion de NTP (sincronizacion de tiempo)
function Check-NTPConfig {
    try {
        $ntpServers = w32tm /query /configuration | Select-String "NtpServer"
        if ($ntpServers) {
            Write-Report "Sincronizacion NTP" "PASS" "Sincronizacion de tiempo configurada con servidores: $($ntpServers -join ', ')."
        } else {
            Write-Report "Sincronizacion NTP" "FAIL" "Configure servidores NTP para sincronizacion de tiempo adecuada."
        }
    } catch {
        Write-Report "Sincronizacion NTP" "FAIL" "Error al comprobar NTP. Detalles: $_"
    }
}

# Revisar puertos abiertos innecesarios
function Check-OpenPorts {
    try {
        $openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }
        $allowedPorts = @(80, 443) # Agregar puertos permitidos
        $unexpectedPorts = $openPorts | Where-Object { $allowedPorts -notcontains $_.LocalPort }
        if ($unexpectedPorts) {
            Write-Report "Puertos abiertos innecesarios" "FAIL" "Revise los siguientes puertos abiertos: $($unexpectedPorts.LocalPort -join ', ')."
        } else {
            Write-Report "Puertos abiertos innecesarios" "PASS" ""
        }
    } catch {
        Write-Report "Puertos abiertos innecesarios" "FAIL" "Error al comprobar puertos abiertos. Detalles: $_"
    }
}

# Validar deshabilitacion de NTLM (autenticacion insegura)
function Check-NTLM {
    try {
        $ntlmSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash"
        if ($ntlmSetting.NoLMHash -eq 1) {
            Write-Report "Deshabilitacion de NTLM" "PASS" "NTLM está deshabilitado."
        } else {
            Write-Report "Deshabilitacion de NTLM" "FAIL" "Configure 'NoLMHash' para deshabilitar NTLM y evitar vulnerabilidades."
        }
    } catch {
        Write-Report "Deshabilitacion de NTLM" "FAIL" "Error al comprobar NTLM. Detalles: $_"
    }
}

# Validar protecciones ASR (Attack Surface Reduction)
function Check-ASRRules {
    try {
        $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
        if ($asrRules -contains "Enabled") {
            Write-Report "Protecciones ASR" "PASS" "Las reglas ASR están habilitadas."
        } else {
            Write-Report "Protecciones ASR" "FAIL" "Habilite las reglas ASR para protegerse contra amenazas modernas."
        }
    } catch {
        Write-Report "Protecciones ASR" "FAIL" "Error al comprobar ASR. Detalles: $_"
    }
}

# Deshabilitar autenticacion anonima
function Check-AnonymousAccess {
    try {
        $anonymousShares = Get-SmbShare | Where-Object { $_.ScopeName -contains "Anonymous" }
        if ($anonymousShares) {
            Write-Report "Acceso anonimo" "FAIL" "Elimine el acceso anonimo a los recursos: $($anonymousShares.Name -join ', ')."
        } else {
            Write-Report "Acceso anonimo" "PASS" ""
        }
    } catch {
        Write-Report "Acceso anonimo" "FAIL" "Error al comprobar el acceso anonimo. Detalles: $_"
    }
}

# Validar reglas de acceso local (LAPS)
# Revisa si el servidor utiliza LAPS (Local Administrator Password Solution) para proteger cuentas locales.
function Check-LAPS {
    try {
        $laps = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS" -Name "Enabled"
        if ($laps.Enabled -eq 1) {
            Write-Report "LAPS habilitado" "PASS" "LAPS está habilitado para proteger contrasenas de cuentas locales."
        } else {
            Write-Report "LAPS habilitado" "FAIL" "Habilite LAPS para gestionar contrasenas locales de forma segura."
        }
    } catch {
        Write-Report "LAPS habilitado" "FAIL" "Error al comprobar LAPS. Detalles: $_"
    }
}


# Ejecutar todas las verificaciones
Check-Firewall
Check-AdminAccount
Check-SMBv1
Check-PasswordPolicy
Check-UAC
Check-RDP
Check-BitLocker
Check-TLS
Check-WindowsUpdates
Check-LMHash
Check-UnnecessaryServices
Check-AuditPolicy
Check-USBRestrictions
Check-ScreenLock
Check-LoginFailures
Check-ExecutionPolicy
Check-PasswordNeverExpires
Check-CriticalServices
Check-InactiveAccounts
Check-OpenPorts
Check-NTPConfig
Check-NTLM
Check-ASRRules
Check-AnonymousAccess
Check-LAPS
