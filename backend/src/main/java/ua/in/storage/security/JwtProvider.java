package ua.in.storage.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtEncoder jwtEncoder;
    private final UserDetailsManagerImp userDetailsManagerImp;
    @Value("${jwt.expiration.time}")
    private Long jwtExpirationInMillis;

    public String generateToken(Authentication authentication) {
        return generateTokenWithUserName( ((User) authentication.getPrincipal()).getUsername());
    }

    public String generateTokenWithUserName(String usermame) {


        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusMillis(jwtExpirationInMillis))
                .subject(usermame)
                .claim("scope", getSetAuthorities(usermame))
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
