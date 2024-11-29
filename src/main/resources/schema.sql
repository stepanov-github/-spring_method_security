CREATE TABLE if not EXISTS PERSONS
(
    name           varchar not null,
    surname        varchar not null,
    age            int     not null,
    phone_number   varchar not null,
    city_of_living varchar not null,
    PRIMARY KEY (name, surname, age)
    );

insert into PERSONS
values ('Ivan', 'Petrov', 21, +7910111111, 'Moscow'),
       ('Ivan', 'Sidorov', 32, +7926222222, 'Dubna'),
       ('Aleksey', 'Ivanov', 18, +79163333333, 'Moscow'),
       ('Dmitriy', 'Petrov', 31, +79104444444, 'Moscow'),
       ('Ivan', 'Aleksandrov', 44, +79165555555, 'Balashikha'),
       ('Dmitriy', 'Ivanov', 35, +79266666666, 'Domodedovo'),
       ('Ivan', 'Sokolov', 60, +79037777777, 'Moscow');
