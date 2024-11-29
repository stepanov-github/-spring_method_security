package ru.home.hibernate.repositiry;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import ru.home.hibernate.entity.PersonKey;
import ru.home.hibernate.entity.Persons;

import java.util.List;
import java.util.Optional;

@Repository
public interface PersonsRepository extends JpaRepository<Persons, PersonKey> {

//    public List<Persons> findByCityOfLiving(String city_of_living);
//    public List<Persons> findByPersonKey_AgeLessThanOrderByPersonKey_Age(int PersonKey_AgeLessThan);
//    public Optional<Persons> findFirst1ByPersonKey_NameAndPersonKey_Surname(String PersonKey_Name, String PersonKey_Surname);

    @Query("SELECT p FROM Persons p WHERE lower(p.cityOfLiving) = lower(:city)")
    public List<Persons> findByCityJPQL(String city);

    @Query("SELECT p FROM Persons p WHERE p.personKey.age < :age ORDER BY p.personKey.age")
    public List<Persons> findByAgeJPQL(int age);

    @Query("SELECT p FROM Persons p WHERE lower(p.personKey.name) = lower(:name) AND lower(p.personKey.surname) = lower(:surname)")
    public Optional<Persons> findByNameSurnameJPQL(String name, String surname, PageRequest pageRequest);


}
