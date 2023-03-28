package ua.in.storage.model.enums;

import org.springframework.security.core.GrantedAuthority;

public enum Permission {
    PERMISSION_READ("read"),
    PERMISSION_WRITE("write"),
    ADMIN("admin"),
    USER("user"),
    NonAUTH("");

    private final String permission;
    Permission(String permission) {
        this.permission = permission;
    }
    public String getAuthority() {
        return permission;
    }
}