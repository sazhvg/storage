package ua.in.storage.model.enums;

import org.springframework.security.core.GrantedAuthority;

public enum Permission/* implements GrantedAuthority*/ {
    PERMISSION_READ("developers:read"),
    PERMISSION_WRITE("developers:write"),
    ROLE_ADMIN("developers:write"),
    ROLE_USER("developers:write"),
    ROLE_NonAUTH("");

    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }

//    @Override
    public String getAuthority() {
        return permission;
    }
}