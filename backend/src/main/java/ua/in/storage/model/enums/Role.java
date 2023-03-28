package ua.in.storage.model.enums;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum Role {

    NonAUTH(Set.of(
            Permission.NonAUTH)),
    USER(Set.of(
            Permission.PERMISSION_READ,
            Permission.USER)),
    ADMIN(Set.of(
            Permission.ADMIN,
            Permission.USER,
            Permission.PERMISSION_READ,
            Permission.PERMISSION_WRITE));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public Set<GrantedAuthority> getAuthorities() {
        return getPermissions().stream().map(permission ->
                        new GrantedAuthority() {
                            @Override
                            public String getAuthority() {
                                return null;
                            }
                        })
                .collect(Collectors.toSet());
    }
}