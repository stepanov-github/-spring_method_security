package ru.home.hibernate.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ru.home.hibernate.entity.Persons;
import ru.home.hibernate.repositiry.PersonsRepository;

import java.util.List;
import java.util.Optional;

@RestController
public class PersonsController {
    private final PersonsRepository personsRepository;

    public PersonsController(PersonsRepository personsRepository) {
        this.personsRepository = personsRepository;
    }

    @GetMapping("/persons/by-city")
    @Secured("ROLE_READ")
    public List<Persons> getPersonsByCity(@RequestParam String city) {
//        return personsRepository.findByCityOfLiving(city);
        return personsRepository.findByCityJPQL(city);
    }

    @GetMapping("/persons/by-age")
    @RolesAllowed("ROLE_WRITE")
    public List<Persons> getPersonsByAge(@RequestParam int age) {
//        return personsRepository.findByPersonKey_AgeLessThanOrderByPersonKey_Age(age);
        return personsRepository.findByAgeJPQL(age);

    }

    @GetMapping("/persons/by-name-surname")
    @PreAuthorize("hasRole('ROLE_WRITE') or hasRole('ROLE_DELETE')")
    public Optional<Persons> getPersonsByAge(@RequestParam String name, @RequestParam String surname) {
//        return personsRepository.findFirst1ByPersonKey_NameAndPersonKey_Surname(name, surname);
        return personsRepository.findByNameSurnameJPQL(name, surname, PageRequest.of(0, 1));
    }
}
