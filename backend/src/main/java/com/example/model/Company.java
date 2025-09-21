package com.example.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "companies")
public class Company {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name")
    private String name;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_creator_id")
    private User userCreator;

    @Column(name = "avatar_url")
    private String avatarUrl;

    @OneToMany(mappedBy = "company", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<CompanyEmployee> employees =  new ArrayList<>();

    public void addEmployee(User user, EmployeeRole role) {
        employees.add(new CompanyEmployee(this, user, role));
    }

    public void removeEmployee(User user) {
        employees.removeIf(employee -> employee.getUser().equals(user));
    }
}
