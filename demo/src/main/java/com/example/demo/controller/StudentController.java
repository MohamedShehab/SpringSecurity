package com.example.demo.controller;

import com.example.demo.student.Student;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

    private static final List<Student> students = Arrays.asList(
            new Student(1, "Mohamed Shehab"),
            new Student(2, "Tamer Hosny"),
            new Student(3, "Ayman noor")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable(required = true) Integer studentId) {
        return students.stream().filter(
                student -> student.getStudentId().equals(studentId)
        ).findFirst().orElseThrow(
                () -> new IllegalStateException("Student " + studentId + "dose not exist!")
        );
    }
}
