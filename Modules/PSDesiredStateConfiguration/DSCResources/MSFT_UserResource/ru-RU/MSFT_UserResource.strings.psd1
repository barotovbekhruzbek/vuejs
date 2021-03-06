# Localized	12/07/2019 11:47 AM (GMT)	303:6.40.20520 	MSFT_UserResource.strings.psd1
# Localized resources for MSFT_UserResource

ConvertFrom-StringData @'
###PSLOC
UserWithName=Пользователь: {0}
RemoveOperation=Удалить
AddOperation=Добавить
SetOperation=Установить
ConfigurationStarted=Запущена конфигурация пользователя {0}.
ConfigurationCompleted=Конфигурация пользователя {0} выполнена успешно.
UserCreated=Пользователь {0} создан успешно.
UserUpdated=Свойства пользователя {0} обновлены успешно.
UserRemoved=Пользователь {0} удален успешно.
NoConfigurationRequired=Пользователь {0} существует на этом узле с требуемыми свойствами. Действия не требуются.
NoConfigurationRequiredUserDoesNotExist=Пользователь {0} не существует на этом узле. Действия не требуются.
InvalidUserName=Использование имени {0} невозможно. Имена не могут целиком состоять из точек и/или пробелов, а также содержать следующие символы: {1}
UserExists=Пользователь с именем {0} существует.
UserDoesNotExist=Пользователь с именем {0} не существует.
PropertyMismatch=Для свойства {0} ожидается значение {1}, но оно равно {2}.
PasswordPropertyMismatch=Значение свойства {0} не совпадает.
AllUserPropertisMatch={0} {1}: все свойства совпадают.
ConnectionError=При попытке использовать API System.DirectoryServices могла возникнуть ошибка подключения.
MultipleMatches=При попытке использовать API System.DirectoryServices могло возникнуть исключение нескольких совпадений.
###PSLOC

'@
