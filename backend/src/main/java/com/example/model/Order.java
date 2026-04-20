package com.example.model;

import com.example.model.enums.DealType;
import com.example.model.enums.OrderStatus;
import com.example.model.enums.PropertyType;
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
@Table(name = "orders")
public class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "company_id")
    private Company company;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "client_id")
    private Client client;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, fetch = FetchType.EAGER, orphanRemoval = true)
    @Builder.Default
    private List<OrderProperty> properties = new ArrayList<>();

    @Column(name = "city")
    private String city;

    @Enumerated(EnumType.STRING)
    @Column(name = "property_type")
    private PropertyType propertyType;

    @Enumerated(EnumType.STRING)
    @Column(name = "deal_type")
    private DealType dealType;

    @Column(name = "description")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private OrderStatus status;

    public void addProperty(OrderProperty orderProperty) {
        properties.add(orderProperty);
    }

    public void removeProperty(OrderProperty orderProperty) {
        properties.remove(orderProperty);
    }

//    public List<Property> getProperties() {
//        return properties.stream()
//                .map(OrderProperty::getProperty)
//                .collect(Collectors.toList());
//    }
}
