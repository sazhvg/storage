package ua.in.storage.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import ua.in.storage.model.enums.Permission;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toSet;

@Service
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtEncoder jwtEncoder;
//    private final UserDetailsServiceImpl userDetailsService;
    private final UserDetailsManagerImp userDetailsManagerImp;
    @Value("${jwt.expiration.time}")
    private Long jwtExpirationInMillis;

    public String generateToken(Authentication authentication) {
        return generateTokenWithUserName( ((User) authentication.getPrincipal()).getUsername());
    }

    public String generateTokenWithUserName(String usermame) {

//        return generateTokenWithUserName(userDetailsManagerImp.loadUserByUsername(
//                (usermame);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusMillis(jwtExpirationInMillis))
//                .subject(userDetails.getUsername())
                .subject(usermame)
//                .claim("scope", userDetailsManagerImp.loadUserByUsername(usermame)
//                        .getAuthorities())
                .claim("scope", getSetAuthorities(usermame))
//                .claim("scope", getSetAuthorities((Set<? extends GrantedAuthority>) userDetails.getAuthorities()))
                .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public Set<String> getSetAuthorities(String username){

        Set<String> listAuthorities = new HashSet<>();
        for (GrantedAuthority grantedAuthority : userDetailsManagerImp
                .loadUserByUsername(username).getAuthorities()){
            listAuthorities.add(grantedAuthority.getAuthority());
        }
        return listAuthorities;
    }

    public Long getJwtExpirationInMillis() {
        return jwtExpirationInMillis;
    }
}
