# -_R-Vision т

Задание 1.

 > Провести частичный анализ OVAL файла от компании RHEL
(https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2) на
первых 3 уязвимостях (патчах). Определить набор объектов, из которых он
строится. Понять основную логику "работы" данного формата.

Нашел на странице GitHub https://github.com/CISecurity/OVALRepo/tree/master/scripts скрипты связанные с форматои OVAL, обнаружил oval_decomposition.py для обработки большого xml файла, который содержит больше 40-50k строк, поэтму использую этот репозиторий и беру от туда код, так же дополнительно для работы беру lib_oval.py. Дальше запускаю скрипт с параметром `-f` - python main.py -f rhel-8.oval.xml

![image](https://github.com/user-attachments/assets/26d59140-5bfb-41bd-89fd-160593472e2e)

И

![image](https://github.com/user-attachments/assets/d0c71f53-ba18-49de-a1cd-ff1ae4b43e5a)


После парсинга мы получаем всё в папку 


![image](https://github.com/user-attachments/assets/a2acd6a2-8722-4552-8f62-befd50c85575)
