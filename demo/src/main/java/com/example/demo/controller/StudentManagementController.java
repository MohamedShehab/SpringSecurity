package com.example.demo.controller;

import com.example.demo.student.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> students = Arrays.asList(
            new Student(1, "Mohamed Shehab"),
            new Student(2, "Tamer Hosny"),
            new Student(3, "Ayman noor")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_USER' , 'ROLE_ADMIN')")
    public List<Student> getAllStudents() {
        return students;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable Integer studentId) {
        System.out.println(studentId);
    }


    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable Integer studentId, @RequestBody Student student) {
        System.out.printf("%s %s", studentId, student);
    }
}
