package ua.in.storage.security;

import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
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
                getAuth(user.getRoles()));
    }

    public Set<GrantedAuthority> getAuth(Set<Role> roles) {
        Set <GrantedAuthority> authorities = new HashSet<>();
//        authorities = roles.stream().forEach(role ->
//                new SimpleGrantedAuthority(role.getPermissions().toString())).collect(Collectors.toSet());




        for (Role role: roles){
            for (Permission permission: role.getPermissions()){
                authorities.add(new SimpleGrantedAuthority(permission.getAuthority()));
            }
        }
        return authorities;
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

//    private Set<SimpleGrantedAuthority> detAuth (Set<Role> roles) {
//        Set <GrantedAuthority> authorities = new HashSet<>();
////        for (Role role: roles) authorities.addAll(role.getAuthorities());
////        return authorities;
////        return  authorities.stream(roles.addAll()).collect(Collectors.toSet());
//        return roles.stream().map(Role::getAuthorities).collect(Collectors.toSet());
//        //        List<String> roles = getAuthorities(user.getRoles()).stream().map(Role::getPermissions).toList();
//    }


//    List<String> roles = getAuthorities(user.getRoles()).stream().map(Role::getPermissions).toList();
}
