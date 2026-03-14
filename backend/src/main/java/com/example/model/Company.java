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

    @OneToMany(mappedBy = "company", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Property> properties = new ArrayList<>();

    public void addEmployee(User user, EmployeeRole role) {
        CompanyEmployee companyEmployee = CompanyEmployee.builder()
                .company(this)
                .user(user)
                .role(role)
                .build();
        employees.add(companyEmployee);
        user.getCompanyEmployees().add(companyEmployee); // Синхронизация обеих сторон
    }

    public void removeEmployee(User user) {
        employees.removeIf(employee -> {
            if (employee.getUser().equals(user)) {
                user.getCompanyEmployees().remove(employee);
                return true;
            }
            return false;
        });
    }

    public EmployeeRole getEmployeeRole(User user) {
        return employees.stream()
                .filter(e -> e.getUser().equals(user))
                .map(CompanyEmployee::getRole)
                .findFirst()
                .orElse(null);
    }

    public void addProperty(Property property) {
        properties.add(property);
    }

    public void removeProperty(Property property) {
        properties.remove(property);
    }
}
