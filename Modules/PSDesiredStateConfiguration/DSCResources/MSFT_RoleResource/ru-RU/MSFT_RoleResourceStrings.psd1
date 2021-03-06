# Localized	12/07/2019 11:47 AM (GMT)	303:6.40.20520 	MSFT_RoleResourceStrings.psd1
# Localized MSFT_RoleResource.psd1

ConvertFrom-StringData @'
###PSLOC
SetTargetResourceInstallwhatIfMessage=Попытка установить компонент {0}
SetTargetResourceUnInstallwhatIfMessage=Попытка удалить компонент {0}
FeatureNotFoundError=Запрошенный компонент {0} не найден на целевом компьютере.
FeatureDiscoveryFailureError=Не удалось получить запрошенные сведения о компоненте {0} с конечного компьютера. В имени компонента не может быть подстановочных символов.
FeatureInstallationFailureError=Не удалось успешно установить компонент {0}.
FeatureUnInstallationFailureError=Не удалось успешно удалить компонент {0}.
QueryFeature=Выполняется запрос компонента {0} с помощью командлета Get-WindowsFeature диспетчера серверов.
InstallFeature=Выполняется попытка установки компонента {0} с помощью командлета Add-WindowsFeature диспетчера серверов.
UninstallFeature=Выполняется попытка удаления компонента {0} с помощью командлета Remove-WindowsFeature диспетчера серверов.
RestartNeeded=Нужно перезапустить конечный компьютер.
GetTargetResourceStartVerboseMessage=Начато выполнение функции Get для компонента {0}.
GetTargetResourceEndVerboseMessage=Завершено выполнение функции Get для компонента {0}.
SetTargetResourceStartVerboseMessage=Начато выполнение функции Set для компонента {0}.
SetTargetResourceEndVerboseMessage=Завершено выполнение функции Set для компонента {0}.
TestTargetResourceStartVerboseMessage=Начато выполнение функции Test для компонента {0}.
TestTargetResourceEndVerboseMessage=Завершено выполнение функции Test для компонента {0}.
ServerManagerModuleNotFoundDebugMessage=Модуль ServerManager не установлен на компьютере.
SkuNotSupported=Установка ролей и компонентов с помощью службы PowerShell Desired State Configuration доступна только в серверных ОС. Она не поддерживается в клиентских системах.
SourcePropertyNotSupportedDebugMessage=Свойство Source в MSFT_RoleResource пропущено, так как оно не поддерживается в этой операционной системе.
EnableServerManagerPSHCmdletsFeature=Обнаружена операционная система Windows Server 2008R2 Core: включен компонент ServerManager-PSH-Cmdlets.
UninstallSuccess=Компонент {0} успешно удален.
InstallSuccess=Компонент {0} успешно установлен.
###PSLOC

'@
