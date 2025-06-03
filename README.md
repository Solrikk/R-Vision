# R-Vision Тестовое задание

## Задание 1.

 > Провести частичный анализ OVAL файла от компании RHEL
(https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2) на
первых 3 уязвимостях (патчах). Определить набор объектов, из которых он
строится. Понять основную логику "работы" данного формата.

Хотя я не очень знаком с форматом OVAL, я изучил репозиторий GitHub https://github.com/CISecurity/OVALRepo/tree/master/scripts со скриптами для работы с OVAL. Там я нашел oval_decomposition.py — скрипт, который разбивает крупные XML-файлы OVAL на отдельные компоненты (объекты, состояния, тесты и т.д.), что значительно упрощает их редактирование и управление. Поскольку мне нужно обработать большой XML-файл размером более 40-50 тысяч строк, я решил использовать код из этого репозитория. Дополнительно я взял библиотеку lib_oval.py для корректной работы. Запускаю скрипт следующей командой: python main.py -f rhel-8.oval.xml

![image](https://github.com/user-attachments/assets/26d59140-5bfb-41bd-89fd-160593472e2e)

Скрипт успешно запустлся и разбивает файл в формате OVAL на составные части и сохраняет их в соответствующих местах. 

![image](https://github.com/user-attachments/assets/d0c71f53-ba18-49de-a1cd-ff1ae4b43e5a)


После парсинга мы получаем всё в папку 

![image](https://github.com/user-attachments/assets/a2acd6a2-8722-4552-8f62-befd50c85575)

- Прочитав более подробно про формат OVAL теперь я знаю что **definitions** содержит определения уязвимостей и патчей. Каждый файл описывает конкретную уязвимость или обновление безопасности для RHEL 8.
- Так же как я знаю **objects** содержит объекты OVAL - описания того, что нужно проверить в системе (файлы, пакеты, реестр и т.д.).
- А так же как  знаю **states** содержит состояния OVAL - описания ожидаемых значений или условий для проверки.
- И **tests** содержит тесты OVAL - логику проверки, которая связывает объекты и состояния.

Разбор 3 патчей:

### 1-ый патч - oval_com.redhat.rhba_def_20191992.xml (CVE-2019-0816)

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



