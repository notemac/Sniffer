# Sniffer for Ethernet II, IPv4, IPv6, ARP, ICMP, IGMPv2, UDP, TCP, HTTP, FTP, SSDP
Анализируются дейтаграммы следующих протоколов: Ethernet II, IPv4, IPv6, ARP, ICMP, IGMPv2, UDP, TCP, HTTP, FTP, SSDP. Вся информация о захваченных пакетах сохраняется в текстовый файл. Имеется возможность посмотреть подробное описание доступных сетевых интерфейсов, в частности, название, IP-адреса версии 4 и 6, маску. Перед началом захвата можно задать выражение для фильтрации пакетов, если необходимо проанализировать только определенные пакеты. Например, если ввести выражение “icmp or udp”, только UDP и ICMP пакеты попадут в выходной файл. Также в файл выводится некоторая статистика (например, количество захваченных пакетов, максимальный и минимальный размеры пакетов).

## Prerequisites
1) Install [WinPcap](https://www.winpcap.org/) (WinPcap_4_1_3.exe)
2) Add path in project (Project -> Properties -> C/C++ -> Additional Include Directories) to header files in folder "WpdPack\Include"

## Additional useful links and books
- [WinPcap Documentation](http://www.winpcap.org/docs/docs_412/html/main.html)
- [Telecommunication & information technologies - телекоммуникационные и информационные технологии](http://book.itep.ru/ )
- Передача  данных  в  компьютерных  сетях  :  учеб.  пособие  / Е. Д. Жиганов,  А. П. Мощевикин.  –  Петрозаводск  :  Изд-во ПетрГУ, 2007. – 156 с.)
- Эффективное программирование TCP/IP. Библиотека программиста: Снейдер. Й. – СПб.: Питер, 2002. – 320 с.
