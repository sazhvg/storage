package ua.in.storage.model;

import jakarta.persistence.*;
import lombok.*;
import ua.in.storage.model.enums.Role;
import ua.in.storage.model.enums.Status;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users"/*,uniqueConstraints = {*//*@UniqueConstraint(columnNames = "username"),*//* @UniqueConstraint(columnNames = "email")}*/)
public class User {
    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long userId;
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID userId;
    @Column(name = "email", unique = true, columnDefinition = "VARCHAR(55) CHECK (email LIKE '%_@__%.__%')", nullable = false)
    private String email;
    @Column(name = "password", nullable = false)
    private String password;
    @Column(name = "created")
    private Instant created;
    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "user_role",
            joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>();
//    @ManyToMany(fetch = FetchType.LAZY)
//    @JoinTable(name = "user_roles",
//            joinColumns = @JoinColumn(name = "user_id"),
//            inverseJoinColumns = @JoinColumn(name = "role_id"))
//    private Set<Role> roles = new HashSet<>();
   @Enumerated(value = EnumType.STRING)
    @Column(name = "status", length = 6)
    private Status status;
}

//https://www.youtube.com/watch?v=FoyAvzU5fO0&t=866s
// Можливо зробити implements UserDetails (відео 4.07)