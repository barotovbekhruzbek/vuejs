# Localized	12/07/2019 11:47 AM (GMT)	303:6.40.20520 	MSFT_ServiceResource.strings.psd1
# Localized resources for MSFT_UserResource

ConvertFrom-StringData @'
###PSLOC
ServiceNotFound=Служба "{0}" не найдена.
CannotStartAndDisable=Не удается запустить и отключить службу.
CannotStopServiceSetToStartAutomatically=Не удается остановить службу и настроить ее для автоматического запуска.
ServiceAlreadyStarted=Служба "{0}" уже запущена, действия не требуются.
ServiceStarted=Служба "{0}" запущена.
ServiceStopped=Служба "{0}" остановлена.
ErrorStartingService=Не удалось запустить службу "{0}". Проверьте путь "{1}", указанный для службы. Сообщение: '{2}'
OnlyOneParameterCanBeSpecified=Можно указать только один из следующих параметров: "{0}", "{1}".
StartServiceWhatIf=Запустить службу
ServiceAlreadyStopped=Служба "{0}" уже остановлена, действия не требуются.
ErrorStoppingService=Не удалось остановить службу "{0}". Сообщение: "{1}"
ErrorRetrievingServiceInformation=Не удалось получить сведения для службы "{0}". Сообщение: "{1}"
ErrorSettingServiceCredential=Не удалось задать учетные данные для службы {0}. Сообщение: "{1}"
SetCredentialWhatIf=Задать учетные данные
SetStartupTypeWhatIf=Задать тип запуска
ErrorSettingServiceStartupType=Не удалось задать тип запуска для службы "{0}". Сообщение: "{1}"
TestUserNameMismatch=Именем пользователя для службы "{0}" является "{1}". Оно не совпадает с "{2}".
TestStartupTypeMismatch=Тип запуска для службы "{0}": "{1}". Он не соответствует "{2}".
MethodFailed=Сбой метода "{0}" для "{1}" с кодом ошибки: "{2}".
ErrorChangingProperty=Не удалось изменить свойство {0}. Сообщение: "{1}"
ErrorSetingLogOnAsServiceRightsForUser=Ошибка при предоставлении "{0}" права на вход в качестве службы. Сообщение: "{1}".
CannotOpenPolicyErrorMessage=Не удается открыть диспетчер политик
UserNameTooLongErrorMessage=Слишком длинное имя пользователя
CannotLookupNamesErrorMessage=Не удалось найти имя пользователя
CannotOpenAccountErrorMessage=Не удалось открыть политику для пользователя
CannotCreateAccountAccessErrorMessage=Не удалось создать политику для пользователя
CannotGetAccountAccessErrorMessage=Не удалось получить права политики пользователя
CannotSetAccountAccessErrorMessage=Не удалось задать права политики пользователя
BinaryPathNotSpecified=При создании службы следует указать путь к исполняемому файлу
ServiceAlreadyExists=Служба "{0}", которую необходимо создать, уже существует
ServiceExistsSamePath=Служба "{0}", которую необходимо создать, уже существует в расположении "{1}"
ServiceNotExists=Служба "{0}" не существует. Чтобы создать службу, укажите путь к исполняемому файлу
ErrorDeletingService=Ошибка удаления службы "{0}"
ServiceDeletedSuccessfully=Служба "{0}" удалена
TryDeleteAgain=Подождите 2 секунды, пока служба удаляется
WritePropertiesIgnored=Служба "{0}" уже существует. Такие свойства с доступом на запись, как Status, DisplayName, Description, Dependencies, для существующих служб будут проигнорированы.
###PSLOC

'@

