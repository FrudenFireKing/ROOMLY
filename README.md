# ROOMLY
RUS/РУС
ROOMLY - это веб-сервис для удобного бронирования переговорных комнат в офисе. 
Презентация: https://docs.google.com/presentation/d/1nd4-lQ-h5AhN-JcS0fhbY4HjLUP6-ED6/edit?usp=sharing&ouid=109050647314759633910&rtpof=true&sd=true

Сервис предоставляет следующие возможности:
- Управление аккаунтами пользователей с тремя уровнями доступа
- Просмотр доступных переговорных комнат с фильтрацией по оборудованию и вместимости
- Бронирование комнат на выбранное время с указанием цели встречи
- Визуализация занятости комнат с помощью графиков
- Уведомления о бронированиях и отменах
- Администрирование системы (добавление/удаление комнат, просмотр всех бронирований)

Реализованные функции: Регистрация и аутентификация пользователей; управление бронированиями (создание, просмотр, отмена); фильтрация комнат по параметрам; визуализация занятости переговорных; административный интерфейс; уведомления по email; Генерация отчетов по использованию помещений

Технологии
- Backend: Python, Flask
- Database: SQLite
- Frontend: HTML, CSS, JavaScript
- Безопасность: хеширование паролей, CSRF защита

Возможное развитие проекта (согласно приложенному изображению)
1.Масштабируемая система бронирования для офисной сети 
   Объединение офисов через распределённую архитектуру. Каждый филиал имеет локальную БД (PostgreSQL+Redis), синхронизируемую через Kafka. Event Sourcing и CRDT обеспечивают согласованность данных. RabbitMQ обрабатывает очереди бронирований, Redis кеширует расписания. Система работает оффлайн с последующей синхронизацией. ClickHouse анализирует загрузку, ML даёт рекомендации. Решение устойчиво к пиковым нагрузкам и обеспечивает бесперебойную работу сети офисов.
2.Мобильное приложение
   Чтобы сделать сервис еще удобнее, возможна разработка нативного мобильного приложения ROOMLY для iOS и Android. Оно будет поддерживать push-уведомления о подтверждении бронирования, изменениях в расписании или отменах встреч. Также предусмотрен оффлайн-доступ к расписанию — пользователи смогут просматривать актуальную информацию о занятости комнат даже без подключения к интернету, а новые бронирования автоматически синхронизируются при восстановлении связи.
3.Расширенная аналитика
   Сервис может получить инструменты для глубокого анализа использования переговорных комнат. Руководство сможет формировать детальные отчеты: загрузка помещений по времени, популярность оборудования, сезонные колебания спроса. На основе этих данных система предложит оптимизацию пространства — например, перепланировку редко используемых комнат. Кроме того, внедрится рекомендательная система: алгоритмы будут подсказывать пользователям оптимальные время и место для встреч, учитывая их предпочтения и статистику занятости.


ENG/АНГ
ROOMLY is a web service for convenient booking of meeting rooms in the office. 
Presentation: https://docs.google.com/presentation/d/1bF_Id52fnwQ6w0DsEO83SpJs_RTLggFJ/edit?usp=sharing&ouid=109050647314759633910&rtpof=true&sd=true

The service provides the following features:
- User account management with three access levels
- View available meeting rooms filtered by equipment and capacity
- Reservation of rooms for the selected time, indicating the purpose of the meeting
- Visualization of room occupancy using graphs
- Notifications of bookings and cancellations
- System administration (adding/removing rooms, viewing all bookings)

Implemented functions: User registration and authentication; booking management (creation, viewing, cancellation); filtering rooms by parameters; visualization of meeting rooms' occupancy; administrative interface; email notifications; Generation of reports on the use of premises

Technologies
- Backend: Python, Flask
- Database: SQLite
- Frontend: HTML, CSS, JavaScript
- Security: password hashing, CSRF protection

Possible development of the project (according to the attached image)
1.Scalable booking system for the office network 
   Combining offices through a distributed architecture. Each branch has a local database (PostgreSQL+Redis), synchronized via Kafka. Event Sourcing and CRDT ensure data consistency. RabbitMQ handles booking queues, and Redis caches schedules. The system works offline with subsequent synchronization. ClickHouse analyzes the download, and ML makes recommendations. The solution is resistant to peak loads and ensures uninterrupted operation of the office network.
2.Mobile application
   To make the service even more convenient, it is possible to develop a native ROOMLY mobile app for iOS and Android. It will support push notifications about booking confirmation, schedule changes, or cancellations. Offline access to the schedule is also provided - users will be able to view up—to-date information about room occupancy even without an Internet connection, and new bookings are automatically synchronized when communication is restored.
3.Advanced Analytics
   The service can get tools for in-depth analysis of the use of meeting rooms. The management will be able to generate detailed reports: time utilization of premises, popularity of equipment, seasonal fluctuations in demand. Based on this data, the system will offer space optimization, for example, redevelopment of rarely used rooms. In addition, a recommendation system will be introduced: algorithms will tell users the optimal time and place for meetings, taking into account their preferences and employment statistics.
