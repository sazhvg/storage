package ua.in.storage.model.enums;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import ua.in.storage.model.enums.Permission;

import java.util.Set;
import java.util.stream.Collectors;

public enum Role {

    NonAUTH(Set.of(Permission.ROLE_NonAUTH)),

    USER(Set.of(Permission.PERMISSION_READ,
            Permission.ROLE_USER)),
    ADMIN(Set.of(Permission.ROLE_ADMIN,
            Permission.ROLE_USER,
            Permission.PERMISSION_READ,
            Permission.PERMISSION_WRITE));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getAuthorities() {
        return getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getAuthority()))
                .collect(Collectors.toSet());
    }
}

//
//@Entity
//@Table(name = "roles")
//public class Role {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long id;
//
//    @Enumerated(EnumType.STRING)
//    @Column(length = 20)
//    private ERole name;
//
//    public Role() {}
//
//    public Role(ERole name) {
//        this.name = name;
//    }
//
//    public Long getId() {
//        return id;
//    }
//
//    public void setId(Long id) {
//        this.id = id;
//    }
//
//    public ERole getName() {
//        return name;
//    }
//
//    public void setName(ERole name) {
//        this.name = name;
//    }
//
//}

//
//public enum ERole {
//    ROLE_USER,
//    ROLE_MODERATOR,
//    ROLE_ADMIN
//}