# Localized	12/07/2019 11:48 AM (GMT)	303:6.40.20520 	PackageProvider.psd1
# Localized PackageProvider.psd1

ConvertFrom-StringData @'
###PSLOC
InvalidIdentifyingNumber=Указанное значение IdentifyingNumber ({0}) не является допустимым Guid
InvalidPath=Указанное значение Path ({0}) имеет недопустимый формат. Допустимые форматы: локальный путь, UNC и HTTP
InvalidNameOrId=Указанные значения Name ({0}) и IdentifyingNumber ({1}) не совпадают со значениями Name ({2}) и IdentifyingNumber ({3}) в MSI-файле
NeedsMoreInfo=Требуется Name или ProductId
InvalidBinaryType=Указанное значение Path ({0}) не указывает на EXE- или MSI-файл и поэтому не поддерживается
CouldNotOpenLog=Не удалось открыть указанный путь LogPath ({0})
CouldNotStartProcess=Не удалось запустить процесс {0}
UnexpectedReturnCode=Код возврата {0} не ожидался. Вероятно, конфигурация неверна
PathDoesNotExist=Не удалось открыть указанный путь Path ({0})
CouldNotOpenDestFile=Не удалось открыть файл {0} для записи
CouldNotGetHttpStream=Не удалось получить поток {0} для файла {1}
ErrorCopyingDataToFile=Обнаружена ошибка при записи содержимого {0} в {1}
PackageConfigurationComplete=Конфигурация пакета завершена
PackageConfigurationStarting=Запуск конфигурации пакета
InstalledPackage=Установленный пакет
UninstalledPackage=Удаленный пакет
NoChangeRequired=Пакет найден в требуемом состоянии, действия не требуются
RemoveExistingLogFile=Удалить существующий файл журнала
CreateLogFile=Создать файл журнала
MountSharePath=Подключить общий ресурс для получения носителя
DownloadHTTPFile=Загрузить носитель по HTTP или HTTPS
StartingProcessMessage=Запуск процесса {0} с аргументами {1}
RemoveDownloadedFile=Удалить загруженный файл
PackageInstalled=Пакет установлен
PackageUninstalled=Пакет удален
MachineRequiresReboot=Данный компьютер требует перезагрузки
PackageDoesNotAppearInstalled=Пакет {0} не установлен
PackageAppearsInstalled=Пакет {0} установлен
PostValidationError=Пакет от {0} установлен, но указанные значения ProductId и/или Name не соответствуют сведениям о пакете
ValidateStandardArgumentsPathwasPath=Validate-StandardArguments, путь был {0}
TheurischemewasuriScheme=Схема URI была {0}
ThepathextensionwaspathExt=Расширение пути было {0}
ParsingProductIdasanidentifyingNumber=Анализ {0} как значение IdentifyingNumber
ParsedProductIdasidentifyingNumber=Проанализировано {0} как {1}
EnsureisEnsure=Обеспечение — {0}
productisproduct=найден продукт {0}
productasbooleanis=продукт как логическое значение — {0}
Creatingcachelocation=Создание расположения кэша
NeedtodownloadfilefromschemedestinationwillbedestName=Нужно скачать файл из {0}, назначением будет {1}
Creatingthedestinationcachefile=Создание конечного файла кэша
Creatingtheschemestream=Создание потока {0}
Settingdefaultcredential=Установка учетных данных по умолчанию
Settingauthenticationlevel=Установка уровня проверки подлинности
Ignoringbadcertificates=Пропуск неверных сертификатов
Gettingtheschemeresponsestream=Получение ответного потока {0}
ErrorOutString=Ошибка: {0}
Copyingtheschemestreambytestothediskcache=Копирование байтов потока {0} в кэш диска
Redirectingpackagepathtocachefilelocation=Перенаправление пути к пакету в расположение файла кэша
ThebinaryisanEXE=Двоичные данные — EXE
Userhasrequestedloggingneedtoattacheventhandlerstotheprocess=Пользователь запросил ведение журнала, необходимо подключить обработчики событий к процессу
StartingwithstartInfoFileNamestartInfoArguments=Запуск {0} с {1}
###PSLOC

'@
