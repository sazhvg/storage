package ua.in.storage.security;

import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.in.storage.model.User;
import ua.in.storage.model.enums.Permission;
import ua.in.storage.model.enums.Role;
import ua.in.storage.model.enums.Status;
import ua.in.storage.repository.UserRepository;

import java.util.*;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class UserDetailsManagerImp implements UserDetailsManager {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<User> userOptional = userRepository.findByEmail(username);
        User user = userOptional
                .orElseThrow(() -> new UsernameNotFoundException("No user " +
                        "Found with username : " + username));
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                getAuth(user.getRoles())
                        .stream().map(permission ->
                                new SimpleGrantedAuthority(permission.getAuthority()))
                        .collect(Collectors.toSet()));//getAuth(user.getRoles()));
    }

    public Set<Permission> getAuth(Set<Role> roles) {

        Set <Permission> permissionSet = new HashSet<>();
        for (Role role: roles) permissionSet.addAll(role.getPermissions());
        return permissionSet;

    }

    @Override
    public void createUser(UserDetails user) {  }
    @Override
    public void updateUser(UserDetails user) {  }
    @Override
    public void deleteUser(String username) {  }
    @Override
    public void changePassword(String oldPassword, String newPassword) {  }
    @Override
    public boolean userExists(String username) {
        return false;
    }
}