
# R-Vision Тестовое задание

## Задание 1: Анализ OVAL файла RHEL

 > Провести частичный анализ OVAL файла от компании RHEL
(https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2) на
первых 3 уязвимостях (патчах). Определить набор объектов, из которых он
строится. Понять основную логику "работы" данного формата.

Хотя я не очень хорошо знаком с форматом OVAL, я изучил репозиторий GitHub — [CISecurity/OVALRepo](https://github.com/CISecurity/OVALRepo) и https://oval.mitre.org/language/index.html, и https://github.com/OVAL-Community/OVAL, содержащий полезные скрипты для работы с этим форматом и подробную информацию об xml-структуре. В частности, меня заинтересовал скрипт `oval_decomposition.py`, предназначенный для разбиения крупных OVAL XML-файлов на отдельные компоненты — объекты, состояния, тесты и т.д. Это значительно упрощает редактирование и последующую работу с таким типом данных.

Поскольку мне необходимо обработать большой XML-файл объёмом более 40–50 тысяч строк, я решил использовать код из указанного репозитория. Для корректной работы скрипта я также подключил библиотеку `lib_oval.py` и `lib_repo.py`.

![image](https://github.com/user-attachments/assets/981c4afa-22bd-4fe9-ab77-888944780fab)

![image](https://github.com/user-attachments/assets/26d59140-5bfb-41bd-89fd-160593472e2e)

Скрипт успешно запустлся и разбивает файл в формате OVAL на составные части и сохраняет их в соответствующих местах. 

![image](https://github.com/user-attachments/assets/d0c71f53-ba18-49de-a1cd-ff1ae4b43e5a)


После парсинга мы получаем все данные в папку по разделам.

![image](https://github.com/user-attachments/assets/a2acd6a2-8722-4552-8f62-befd50c85575)

- Прочитав более подробно про формат OVAL теперь я знаю что **definitions** (`определяет что проверять`) содержит определения уязвимостей и патчей. Каждый файл описывает конкретную уязвимость или обновление безопасности для RHEL 8.
- Так же как теперь я знаю **objects** (`что именно искать в системе`) содержит объекты OVAL - описания того, что нужно проверить в системе (файлы, пакеты, реестр и т.д.).
- А так же как знаю **states** (`с чем сравнивать найденное`) содержит состояния OVAL - описания ожидаемых значений или условий для проверки.
- И **tests** (`как проверять`) содержит тесты OVAL - логику проверки, которая связывает объекты и состояния. 

Разбор 3 патчей:

---

### 1. Патч oval_com.redhat.rhba_def_20191992.xml RHBA-2019:1992 (CVE-2019-0816)

```xml
<oval-def:definition xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" class="patch" id="oval:com.redhat.rhba:def:20191992" version="635">
<oval-def:metadata>
<oval-def:title>RHBA-2019:1992: cloud-init bug fix and enhancement update (Moderate)</oval-def:title>
<oval-def:affected family="unix">
<oval-def:platform>Red Hat Enterprise Linux 8</oval-def:platform>
</oval-def:affected>
<oval-def:reference ref_id="RHBA-2019:1992" ref_url="https://access.redhat.com/errata/RHBA-2019:1992" source="RHSA"/>
<oval-def:reference ref_id="CVE-2019-0816" ref_url="https://access.redhat.com/security/cve/CVE-2019-0816" source="CVE"/>
<oval-def:description>The cloud-init packages provide a set of init scripts for cloud instances. Cloud instances need special scripts to run during initialization to retrieve and install SSH keys, and to let the user run various scripts. Users of cloud-init are advised to upgrade to these updated packages.</oval-def:description>
<oval-def:advisory from="secalert@redhat.com">
<oval-def:severity>Moderate</oval-def:severity>
<oval-def:rights>Copyright 2019 Red Hat, Inc.</oval-def:rights>
<oval-def:issued date="2019-07-30"/>
<oval-def:updated date="2019-07-30"/>
<oval-def:cve cvss3="5.4/CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" cwe="CWE-285" href="https://access.redhat.com/security/cve/CVE-2019-0816" impact="moderate" public="20190305">CVE-2019-0816</oval-def:cve>
<oval-def:bugzilla href="https://bugzilla.redhat.com/1680165" id="1680165">cloud-init: extra ssh keys added to authorized_keys on the Azure platform</oval-def:bugzilla>
<oval-def:affected_cpe_list>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::appstream</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::crb</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::highavailability</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::nfv</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::realtime</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::resilientstorage</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::sap</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::sap_hana</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::supplementary</oval-def:cpe>
<oval-def:cpe>cpe:/o:redhat:enterprise_linux:8</oval-def:cpe>
<oval-def:cpe>cpe:/o:redhat:enterprise_linux:8::baseos</oval-def:cpe>
</oval-def:affected_cpe_list>
</oval-def:advisory>
</oval-def:metadata>
<oval-def:criteria operator="OR">
<oval-def:criterion comment="Red Hat Enterprise Linux must be installed" test_ref="oval:com.redhat.rhba:tst:20191992005"/>
<oval-def:criteria operator="AND">
<oval-def:criterion comment="cloud-init is earlier than 0:18.5-1.el8.4" test_ref="oval:com.redhat.rhba:tst:20191992001"/>
<oval-def:criterion comment="cloud-init is signed with Red Hat redhatrelease2 key" test_ref="oval:com.redhat.rhba:tst:20191992002"/>
<oval-def:criteria operator="OR">
<oval-def:criterion comment="Red Hat Enterprise Linux 8 is installed" test_ref="oval:com.redhat.rhba:tst:20191992003"/>
<oval-def:criterion comment="Red Hat CoreOS 4 is installed" test_ref="oval:com.redhat.rhba:tst:20191992004"/>
</oval-def:criteria>
</oval-def:criteria>
</oval-def:criteria>
</oval-def:definition>
```

Перехожу на сайт https://access.redhat.com/security/cve/CVE-2019-0816 и читаю проблему:
>A security feature bypass exists in Azure SSH Keypairs, due to a change in the provisioning logic for some Linux images that use cloud-init, aka 'Azure SSH Keypairs Security Feature Bypass Vulnerability'.

Как я знаю это большая проблема котора могла развиться к неавторизованному доступу в систему и последующему захвату важных данных системы. 

Такое неожиданное поведение возникает из-за изменения логики подготовки конкретных операционных систем. Это системы, которые используют **cloud-init** и которые непреднамеренно устанавливают открытый ключ из всех сертификатов, доступных виртуальной машине, в файл ssh-authorized-keys во время создания виртуальной машины.

В связи с этим патч сведетельствует об обновление cloud-init до версии `0:18.5-1.el8.4` или выше.

### Разбор оценки CVSS v3 (CVE-2019-0816)

| Метрика | Red Hat | NVD |
|---------|---------|-----|
| **Базовая оценка CVSS v3** | **5.4** | **5.1** |
| Вектор атаки | Сеть | Локальный |
| Сложность атаки | Низкая | Высокая |
| Требуемые привилегии | Низкие | Отсутствуют |
| Взаимодействие с пользователем | Отсутствует | Отсутствует |
| Область воздействия | Неизменная | Неизменная |
| **Влияние на конфиденциальность** | **Низкое** | Отсутствует |
| Влияние на целостность | Низкое | **Высокое** |
| Влияние на доступность | Отсутствует | Отсутствует |


Из этого вы можем сделать более конткретны заключения:

#### Основная информация
- **Уязвимость:** CVE-2019-0816
- **Компонент:** cloud-init
- **Критичность:** Moderate (Умеренная)
- **Платформа:** Red Hat Enterprise Linux 8

#### Описание проблемы
Уязвимость в Azure SSH Keypairs связана с изменением логики подготовки некоторых Linux-образов, использующих cloud-init.

**Суть проблемы:**
> A security feature bypass exists in Azure SSH Keypairs, due to a change in the provisioning logic for some Linux images that use cloud-init, aka 'Azure SSH Keypairs Security Feature Bypass Vulnerability'.

**Потенциальные риски:**
- Неавторизованный доступ к системе
- Возможность захвата важных данных
- Непреднамеренная установка публичных ключей из всех доступных сертификатов ВМ

#### Техническое решение
**Обновление пакета:** cloud-init до версии `0:18.5-1.el8.4` или выше

## Исправление:
Патч исправляет логику обработки метаданных Azure для SSH-ключей и улучшает процесс инициализации облачных экземпляров.


---

### 2. Патч oval_com.redhat.rhba_def_20192715.xml RHBA-2019:2715 (CVE-2019-14378)

```xml
<oval-def:definition xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" class="patch" id="oval:com.redhat.rhba:def:20192715" version="637">
<oval-def:metadata>
<oval-def:title>RHBA-2019:2715: virt:rhel bug fix update (Important)</oval-def:title>
<oval-def:affected family="unix">
<oval-def:platform>Red Hat Enterprise Linux 8</oval-def:platform>
</oval-def:affected>
<oval-def:reference ref_id="RHBA-2019:2715" ref_url="https://access.redhat.com/errata/RHBA-2019:2715" source="RHSA"/>
<oval-def:reference ref_id="CVE-2019-14378" ref_url="https://access.redhat.com/security/cve/CVE-2019-14378" source="CVE"/>
<oval-def:description>Bug Fix(es): * qemu-kvm core dumped after hotplug the deleted disk with iothread parameter (BZ#1718992) * Detached device when trying to upgrade USB device firmware when in doing USB Passthrough via QEMU (BZ#1719228)</oval-def:description>
<oval-def:advisory from="secalert@redhat.com">
<oval-def:severity>Important</oval-def:severity>
<oval-def:rights>Copyright 2019 Red Hat, Inc.</oval-def:rights>
<oval-def:issued date="2019-09-12"/>
<oval-def:updated date="2019-09-12"/>
<oval-def:cve cvss3="7.0/CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H" cwe="CWE-122" href="https://access.redhat.com/security/cve/CVE-2019-14378" impact="important" public="20190728">CVE-2019-14378</oval-def:cve>
<oval-def:bugzilla href="https://bugzilla.redhat.com/1734745" id="1734745">QEMU: slirp: heap buffer overflow during packet reassembly</oval-def:bugzilla>
<oval-def:affected_cpe_list>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::appstream</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::crb</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::highavailability</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::nfv</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::realtime</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::resilientstorage</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::sap</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::sap_hana</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::supplementary</oval-def:cpe>
<oval-def:cpe>cpe:/o:redhat:enterprise_linux:8</oval-def:cpe>
<oval-def:cpe>cpe:/o:redhat:enterprise_linux:8::baseos</oval-def:cpe>
</oval-def:affected_cpe_list>
</oval-def:advisory>
</oval-def:metadata>
```

Перехожу на сайт https://access.redhat.com/security/cve/CVE-2019-14378 и читаю проблему:

>A heap buffer overflow issue was found in the SLiRP networking implementation of the QEMU emulator. This flaw occurs in the ip_reass() routine while reassembling incoming packets if the first fragment is bigger than the m->m_dat[] buffer. An attacker could use this flaw to crash the QEMU process on the host, resulting in a Denial of Service or potentially executing arbitrary code with privileges of the QEMU process.

После некоторых изучениений проблемы я понял, что уязвимость обнаруженая в компоненте QEMU (slirp) — используется для сетевой виртуализации, в последствие атакующий может вызвать сбой приложения (crash) или, потенциально, выполнить произвольный код на хосте (в зависимости от конфигурации).


### Разбор оценки CVSS v3 (CVE-2019-14378)

| Метрика | Red Hat | NVD |
|---------|---------|-----|
| **Базовая оценка CVSS v3** | **7** | **8.8** |
| Вектор атаки | Локальный | Сеть |
| Сложность атаки | Высокая | Низкая |
| Требуемые привилегии | Низкие | Низкие |
| Взаимодействие с пользователем | Отсутствует | Отсутствует |
| Область воздействия | Изменная | Неизменная |
| Влияние на конфиденциальность | Низкое | **Высокое** |
| Влияние на целостность | Низкое | **Высокое** |
| **Влияние на доступность** | **Высокое** | **Высокое** |

Из этого вы можем сделать более конткретны заключения:

#### Основная информация
- **Уязвимость:** CVE-2019-14378
- **Компонент:** QEMU (виртуализация)
- **Критичность:** Important (Важная)
- **CVSS v3:** 7.0 (Высокая)
- **Платформа:** Red Hat Enterprise Linux 8
- **CWE:** CWE-122 (Heap-based Buffer Overflow)

#### Описание проблемы
Уязвимость связана с переполнением буфера в CWE-122 в компоненте SLIRP библиотеки QEMU во время сборки пакетов.

**Технические детали:**
- **Компонент:** QEMU: slirp (сетевая подсистема виртуализации)  
- **Тип уязвимости:** Переполнение буфера в CWE-122 во время сборки пакетов

## Исправление:
Патч исправляет множество компонентов виртуализации, включая:
- **qemu-kvm** до версии `15:2.12.0-65.module+el8.0.0+4084+cceb9f44.5`
- **libvirt** до версии `0:4.5.0-24.3.module+el8.0.0+4084+cceb9f44`



---

### 3. Патч oval_com.redhat.rhba_def_20193384.xml RHBA-2019:3384: Ruby 2.5 (CVE-2019-8320###CVE-2019-8321###CVE-2019-8322###CVE-2019-8323###CVE-2019-8325)

```xml

<oval-def:definition xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" class="patch" id="oval:com.redhat.rhba:def:20193384" version="639">
<oval-def:metadata>
<oval-def:title>RHBA-2019:3384: ruby:2.5 bug fix and enhancement update (Moderate)</oval-def:title>
<oval-def:affected family="unix">
<oval-def:platform>Red Hat Enterprise Linux 8</oval-def:platform>
</oval-def:affected>
<oval-def:reference ref_id="RHBA-2019:3384" ref_url="https://access.redhat.com/errata/RHBA-2019:3384" source="RHSA"/>
<oval-def:reference ref_id="CVE-2019-8320" ref_url="https://access.redhat.com/security/cve/CVE-2019-8320" source="CVE"/>
<oval-def:reference ref_id="CVE-2019-8321" ref_url="https://access.redhat.com/security/cve/CVE-2019-8321" source="CVE"/>
<oval-def:reference ref_id="CVE-2019-8322" ref_url="https://access.redhat.com/security/cve/CVE-2019-8322" source="CVE"/>
<oval-def:reference ref_id="CVE-2019-8323" ref_url="https://access.redhat.com/security/cve/CVE-2019-8323" source="CVE"/>
<oval-def:reference ref_id="CVE-2019-8325" ref_url="https://access.redhat.com/security/cve/CVE-2019-8325" source="CVE"/>
<oval-def:description>For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.1 Release Notes linked from the References section.</oval-def:description>
<oval-def:advisory from="secalert@redhat.com">
<oval-def:severity>Moderate</oval-def:severity>
<oval-def:rights>Copyright 2019 Red Hat, Inc.</oval-def:rights>
<oval-def:issued date="2019-11-05"/>
<oval-def:updated date="2019-11-05"/>
<oval-def:cve cvss3="7.4/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" cwe="CWE-22" href="https://access.redhat.com/security/cve/CVE-2019-8320" impact="moderate" public="20190305">CVE-2019-8320</oval-def:cve>
<oval-def:cve cvss3="5.3/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" cwe="CWE-88" href="https://access.redhat.com/security/cve/CVE-2019-8321" impact="low" public="20190305">CVE-2019-8321</oval-def:cve>
<oval-def:cve cvss3="5.3/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" cwe="CWE-88" href="https://access.redhat.com/security/cve/CVE-2019-8322" impact="low" public="20190305">CVE-2019-8322</oval-def:cve>
<oval-def:cve cvss3="5.3/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" cwe="CWE-88" href="https://access.redhat.com/security/cve/CVE-2019-8323" impact="low" public="20190305">CVE-2019-8323</oval-def:cve>
<oval-def:cve cvss3="5.3/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" cwe="CWE-88" href="https://access.redhat.com/security/cve/CVE-2019-8325" impact="low" public="20190305">CVE-2019-8325</oval-def:cve>
<oval-def:bugzilla href="https://bugzilla.redhat.com/1692512" id="1692512">rubygems: Delete directory using symlink when decompressing tar</oval-def:bugzilla>
<oval-def:bugzilla href="https://bugzilla.redhat.com/1692514" id="1692514">rubygems: Escape sequence injection vulnerability in verbose</oval-def:bugzilla>
<oval-def:bugzilla href="https://bugzilla.redhat.com/1692516" id="1692516">rubygems: Escape sequence injection vulnerability in gem owner</oval-def:bugzilla>
<oval-def:bugzilla href="https://bugzilla.redhat.com/1692519" id="1692519">rubygems: Escape sequence injection vulnerability in API response handling</oval-def:bugzilla>
<oval-def:bugzilla href="https://bugzilla.redhat.com/1692522" id="1692522">rubygems: Escape sequence injection vulnerability in errors</oval-def:bugzilla>
<oval-def:affected_cpe_list>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::appstream</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::crb</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::highavailability</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::nfv</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::realtime</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::resilientstorage</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::sap</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::sap_hana</oval-def:cpe>
<oval-def:cpe>cpe:/a:redhat:enterprise_linux:8::supplementary</oval-def:cpe>
<oval-def:cpe>cpe:/o:redhat:enterprise_linux:8</oval-def:cpe>
<oval-def:cpe>cpe:/o:redhat:enterprise_linux:8::baseos</oval-def:cpe>
</oval-def:affected_cpe_list>
</oval-def:advisory>
</oval-def:metadata>
```

1. (**CVE-2019-8320**) Перехожу на сайт https://bugzilla.redhat.com/show_bug.cgi?id=1692512 или на https://access.redhat.com/security/cve/CVE-2019-8320 и читаю проблему:
>A Directory Traversal issue was discovered in RubyGems 2.7.6 and later through 3.0.2. Before making new directories or touching files (which now include path-checking code for symlinks), it would delete the target destination. If that destination was hidden behind a symlink, a malicious gem could delete arbitrary files on the user’s machine, presuming the attacker could guess at paths. Given how frequently gem is run as sudo, and how predictable paths are on modern systems (/tmp, /usr, etc.), this could likely lead to data loss or an unusable system.

2. (**CVE-2019-8321**) Перехожу на сайт https://bugzilla.redhat.com/show_bug.cgi?id=1692514 или на и читаю проблему:
>An issue was discovered in RubyGems 2.6 and later through 3.0.2. Since Gem::UserInteraction#verbose calls say without escaping, escape sequence injection is possible.

3. (**CVE-2019-8322**) Перехожу на сайт https://bugzilla.redhat.com/show_bug.cgi?id=1692516 или на и читаю проблему:
>An issue was discovered in RubyGems 2.6 and later through 3.0.2. The gem owner command outputs the contents of the API response directly to stdout. Therefore, if the response is crafted, escape sequence injection may occur.

4. (**CVE-2019-8323**) Перехожу на сайт https://bugzilla.redhat.com/show_bug.cgi?id=1692519 и читаю проблему:
>An issue was discovered in RubyGems 2.6 and later through 3.0.2. Gem::GemcutterUtilities#with_response may output the API response to stdout as it is. Therefore, if the API side modifies the response, escape sequence injection may occur.

5. (**CVE-2019-8325**) Перехожу на сайт https://bugzilla.redhat.com/show_bug.cgi?id=1692522 и читаю проблему:
>An issue was discovered in RubyGems 2.6 and later through 3.0.2. Since Gem::CommandManager#run calls alert_error without escaping, escape sequence injection is possible. (There are many ways to cause an error.)

Рассмотрим всё по мере опасности:

**CVE-2019-8320:**
- **Суть:** Уязвимость Directory Traversal в RubyGems 2.7.6 и выше
- **Механизм:** При создании новых директорий или файлов, RubyGems удаляет целевую директорию без проверки симлинков
- **Риск:** Злоумышленник может удалить произвольные файлы в системе через вредоносный gem

```
 alert_error "While executing gem ... (#{ex.class})\n #{ex}"
```

### Разбор оценки CVSS v3 (CVE-2019-8320)

| Метрика | Red Hat | NVD |
|---------|---------|-----|
| **Базовая оценка CVSS v3** | **7.4** | **7.4** |
| Вектор атаки | Сеть | Сеть |
| Сложность атаки | Высокая | Высокая |
| Требуемые привилегии | Отсутствуют | Отсутствуют |
| Взаимодействие с пользователем | Отсутствует | Отсутствует |
| Область воздействия | Неизменная | Неизменная |
| Влияние на конфиденциальность | Отсутствует | Отсутствует |
| **Влияние на целостность** | **Высокое** | **Высокое** |
| **Влияние на доступность** | **Высокое** | **Высокое** |


И следующие:

**CVE-2019-8321, CVE-2019-8322, CVE-2019-8323, CVE-2019-8325:**
- **Суть:** Инъекция escape-последовательностей в различных компонентах RubyGems
- **Компоненты:** verbose mode, gem owner, API response handling, error messages
- **Риск:** Возможность выполнения произвольных команд через терминальные escape-последовательности

### Разбор оценки CVSS v3 (CVE-2019-8321)

| Метрика | Red Hat | NVD |
|---------|---------|-----|
| **Базовая оценка CVSS v3** | **5.3** | **7.5** |
| Вектор атаки | Сеть | Сеть |
| Сложность атаки | Низкая | Низкая |
| Требуемые привилегии | Отсутствуют | Отсутствуют |
| Взаимодействие с пользователем | Отсутствует | Отсутствует |
| Область воздействия | Неизменная | Неизменная |
| Влияние на конфиденциальность | Отсутствует | Отсутствует |
| **Влияние на целостность** | **Низкое** | **Высокое** |
| Влияние на доступность | Отсутствует | Отсутствует |

---

### Разбор оценки CVSS v3 (CVE-2019-8322)

| Метрика | Red Hat | NVD |
|---------|---------|-----|
| **Базовая оценка CVSS v3** | **5.3** | **7.5** |
| Вектор атаки | Сеть | Сеть |
| Сложность атаки | Низкая | Низкая |
| Требуемые привилегии | Отсутствуют | Отсутствуют |
| Взаимодействие с пользователем | Отсутствует | Отсутствует |
| Область воздействия | Неизменная | Неизменная |
| Влияние на конфиденциальность | Отсутствует | Отсутствует |
| **Влияние на целостность** | **Низкое** | **Высокое** |
| Влияние на доступность | Отсутствует | Отсутствует |


---

### Разбор оценки CVSS v3 (CVE-2019-8323)

| Метрика | Red Hat | NVD |
|---------|---------|-----|
| **Базовая оценка CVSS v3** | **5.3** | **7.5** |
| Вектор атаки | Сеть | Сеть |
| Сложность атаки | Низкая | Низкая |
| Требуемые привилегии | Отсутствуют | Отсутствуют |
| Взаимодействие с пользователем | Отсутствует | Отсутствует |
| Область воздействия | Неизменная | Неизменная |
| Влияние на конфиденциальность | Отсутствует | Отсутствует |
| **Влияние на целостность** | **Низкое** | **Высокое** |
| Влияние на доступность | Отсутствует | Отсутствует |

---

### Разбор оценки CVSS v3 (CVE-2019-8325)

| Метрика | Red Hat | NVD |
|---------|---------|-----|
| **Базовая оценка CVSS v3** | **5.3** | **7.5** |
| Вектор атаки | Сеть | Сеть |
| Сложность атаки | Низкая | Низкая |
| Требуемые привилегии | Отсутствуют | Отсутствуют |
| Взаимодействие с пользователем | Отсутствует | Отсутствует |
| Область воздействия | Неизменная | Неизменная |
| Влияние на конфиденциальность | Отсутствует | Отсутствует |
| **Влияние на целостность** | **Низкое** | **Высокое** |
| Влияние на доступность | Отсутствует | Отсутствует |


## Исправление:
Патч исправляет:
1. **Directory Traversal** - добавлена проверка путей и симлинков перед операциями с файлами
2. **Escape Sequence Injection** - добавлено экранирование выводимых данных во всех уязвимых компонентах
3. **Улучшена валидация входных данных** для предотвращения инъекций

---

## Задание 2
 
>Описать текстом объекты, которые были найдены и для чего онииспользуются. (Не более 2-3 фраз по каждому объекту).


### Найденные объекты OVAL в repo.:

- **Definitions** - Содержат описания конкретных уязвимостей, патчей или проверок безопасности (название, описание, CVE). Служат основной точкой входа для идентификации проблем безопасности в системе.
- **Objects** - Указывают конкретные элементы системы, которые необходимо проверить (файлы, пакеты, реестр, процессы). Содержат пути к файлам, имена пакетов или другие идентификаторы для поиска в системе. Представляют собой "что искать" в процессе сканирования безопасности.
- **States** - Определяют ожидаемые значения или условия для сравнения найденных объектов. Содержат критерии оценки (версии пакетов, права доступа, содержимое файлов).
- **Tests** - Описывают логику проверки конкретных условий в системе, связывая объекты и состояния. Определяют какие объекты нужно найти и с какими состояниями их сравнить.


![image](https://github.com/user-attachments/assets/a2acd6a2-8722-4552-8f62-befd50c85575)

---

## Задание 3

>В рамках каждого определения уязвимости, есть критерии по ее выявлению: какие из критериев на ваш взгляд лишние?

В основном, я имею мало опыта, чтобы рассуждать о структуре OVAL, но например, в третьем патче (**Ruby**) есть 5 разных CVE, но все они касаются одного компонента и исправляются одним обновлением. Их можно было бы сгруппировать связанные уязвимости или сослаться на основную тему. 

---

## Задание 4

>Предложить и кратко описать свой вариант по упрощению формата для описания уязвимости вместе с проверками.

Мы могли бы заменить XML на JSON, потому чо он намного проще для понимания данных, из-за его упрощенный структуры, так же стандартные JSON-библиотеки есть во всех языках программирования, для того чтобы их можно было удобно обрабатывать различными скриптами и приложениями. Так же при желании можно добавлять различные модули и расширения для json структур.

Пример:

```json
[
  {
    "vulnerability": {
      "id": "CVE-2019-0816",
      "title": "RHBA-2019:1992: cloud-init bug fix and enhancement update (Moderate)",
      "severity": "MODERATE",
      "cvss_score": 5.4,
      "description": "The cloud-init packages provide a set of init scripts for cloud instances. Cloud instances need special scripts to run during initialization to retrieve and install SSH keys, and to let the user run various scripts.\n\nUsers of cloud-init are advised to upgrade to these updated packages.",
      "affected_platforms": [
        "Red Hat Enterprise Linux 8"
      ],
      "checks": {
        "package_check": {
          "type": "package_version",
          "package_name": "unknown",
          "vulnerable_versions": "unknown",
          "fixed_version": "unknown"
        }
      },
      "remediation": {
        "action": "update_package",
        "package": "unknown",
        "target_version": "latest",
        "commands": [
          "yum update"
        ]
      },
      "references": [
        "https://access.redhat.com/security/cve/CVE-2019-0816",
        "https://bugzilla.redhat.com/1680165"
      ]
```

- `vulnerability` - базовая информация о CVE
- `checks` - различные типы проверок (пакеты, файлы, процессы)
- `remediation` - шаги исправления
- `references` - ссылки

## Задание 5 

>После выполненного в предыдущей пунктах анализа, необходимо
разработать приложение на языке Python, которое произведет разбор
(парсинг) OVAL-файла (достаточно сделать только первые 3 и связанными с
ними объекты) и преобразует его в упрощенный формат.


- Использовал ресурсы для написания кода - https://github.com/CISecurity/OVALRepo /// https://github.com/CISecurity/OVALRepo/blob/master/scripts/oval_decomposition.py /// https://oval.mitre.org/index.html
- Так же очень помог этот репозиторий - https://github.com/ribeiroit/python-oval 

### Код Phyton:

```Python

import xml.etree.ElementTree as ET ### выбрал для парсинга XML файлов
import json ### Выбрал библиотеку для работы с JSON

def parse_oval_patches(xml_file, num_patches=3): ### парсим XML файл с помощью ElementTree
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    ns = {'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'} ### определяю namespace для OVAL XML
     
    patches = [] ### создаю список для хранения информации о патчах
    definitions = root.findall('.//oval:definition[@class="patch"]', ns) 
    
    for i, definition in enumerate(definitions[:num_patches]): ### обрабатываем каждый найденный патч
        patch = { ### создаю словарь для хранения информации о патче
            'id': definition.get('id'),
            'version': definition.get('version'),
            'title': '',
            'severity': '',
            'description': '',
            'cves': [],
            'platform': '',
            'issued_date': '',
            'updated_date': '',
            'bugzilla_links': []
        }
        
        metadata = definition.find('oval:metadata', ns) ### ищу блок метаданных в определении патча
        if metadata is not None: ### проверка на нахождение
            title = metadata.find('oval:title', ns)
            if title is not None: ### извлекаю название патча
                patch['title'] = title.text
            
            platform = metadata.find('.//oval:platform', ns) ### извлекаю информацию о платформе
            if platform is not None:
                patch['platform'] = platform.text
            
            desc = metadata.find('oval:description', ns) ### извлекаю описание патча
            if desc is not None:
                patch['description'] = desc.text
            
            advisory = metadata.find('oval:advisory', ns) ### обрабатываю блок advisory с подробной информацией
            if advisory is not None:
                severity = advisory.find('oval:severity', ns) ### извлекаю уровень критичности
                if severity is not None:
                    patch['severity'] = severity.text
                
                issued = advisory.find('oval:issued', ns) ### извлекаю дату выпуска патча
                if issued is not None:
                    patch['issued_date'] = issued.get('date')
                
                updated = advisory.find('oval:updated', ns) ### извлекаю дату обновления
                if updated is not None:
                    patch['updated_date'] = updated.get('date')
                
                for cve in advisory.findall('oval:cve', ns): ### обрабатываю все CVE связанные с патчем
                    cve_info = {
                        'id': cve.text,
                        'cvss3': cve.get('cvss3'),
                        'impact': cve.get('impact'),
                        'href': cve.get('href')
                    }
                    patch['cves'].append(cve_info)
                
                for bugzilla in advisory.findall('oval:bugzilla', ns): ### обрабатываю ссылки на баги в Bugzilla
                    bug_info = {
                        'id': bugzilla.get('id'),
                        'href': bugzilla.get('href'),
                        'description': bugzilla.text
                    }
                    patch['bugzilla_links'].append(bug_info)
        
        patches.append(patch) ### ддобавляю обработанный патч в общий список
    
    return patches ### возвращаю список всех обработанных патчей

def convert_to_simplified_format(patches): ### конвертация сложной структуры OVAL в упрощенный JSON формат
    simplified_vulnerabilities = [] ### создаю список для упрощенных уязвимостей
    
    for patch in patches: ### обрабатываю каждый патч
        for cve in patch['cves']:
            vulnerability = {
                "vulnerability": { ### создаю упрощенную структуру данных
                    "id": cve['id'],
                    "title": patch['title'],
                    "severity": patch['severity'].upper(),
                    "cvss_score": float(cve['cvss3'].split('/')[0]) if cve['cvss3'] else 0.0,
                    "description": patch['description'],
                    "affected_platforms": [patch['platform']],
                    "checks": {
                        "package_check": { ### блок проверок
                            "type": "package_version",
                            "package_name": "unknown",
                            "vulnerable_versions": "unknown",
                            "fixed_version": "unknown"
                        }
                    },
                    "remediation": { ### блок исправления
                        "action": "update_package",
                        "package": "unknown",
                        "target_version": "latest",
                        "commands": ["yum update"]
                    },
                    "references": [cve['href']] + [bug['href'] for bug in patch['bugzilla_links']] ### обьеденяю ссылки на CVE и Bugzilla
                }
            }
            simplified_vulnerabilities.append(vulnerability)
    
    return simplified_vulnerabilities

def main():
    print("Парсинг первых 3 патчей из OVAL XML файла...")
    
    patches = parse_oval_patches('attached_assets/rhel-8.oval.xml', 3) ### парсинг OVAL файла и получаю первые 3 патча
    
    simplified = convert_to_simplified_format(patches)
    
    with open('vulnerabilities.json', 'w', encoding='utf-8') as f:
        json.dump(simplified, f, ensure_ascii=False, indent=2)
    
    print(f"Успешно обработано {len(patches)} патчей и {len(simplified)} уязвимостей:")
    for patch in patches:
        print(f"- {patch['id']}: {patch['title']}")
        print(f"  Severity: {patch['severity']}")
        print(f"  CVEs: {len(patch['cves'])}")
        print()

if __name__ == "__main__":
    main()
```



### Пример результата:

```JSON
[
  {
    "vulnerability": {
      "id": "CVE-2019-0816",
      "title": "RHBA-2019:1992: cloud-init bug fix and enhancement update (Moderate)",
      "severity": "MODERATE",
      "cvss_score": 5.4,
      "description": "The cloud-init packages provide a set of init scripts for cloud instances. Cloud instances need special scripts to run during initialization to retrieve and install SSH keys, and to let the user run various scripts.\n\nUsers of cloud-init are advised to upgrade to these updated packages.",
      "affected_platforms": [
        "Red Hat Enterprise Linux 8"
      ],
      "checks": {
        "package_check": {
          "type": "package_version",
          "package_name": "unknown",
          "vulnerable_versions": "unknown",
          "fixed_version": "unknown"
        }
      },
      "remediation": {
        "action": "update_package",
        "package": "unknown",
        "target_version": "latest",
        "commands": [
          "yum update"
        ]
      },
      "references": [
        "https://access.redhat.com/security/cve/CVE-2019-0816",
        "https://bugzilla.redhat.com/1680165"
      ]
```
