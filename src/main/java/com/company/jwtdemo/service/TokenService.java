package com.company.jwtdemo.service;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;


    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }


    public String generateToken(Authentication authentication) {
        Instant now = Instant.now(); // time now (для опеределения с какого по какое будет действовать токен)

        String scope = authentication.getAuthorities().stream() //get roles(f.e ROLE_USER, ROLE_ADMIN)
                .map(GrantedAuthority::getAuthority) // извлекаем названия ролей
                .collect(Collectors.joining(" ")); // обьединяем в строку через пробел

        JwtClaimsSet claims = JwtClaimsSet.builder() //Создаём содержимое токена
                .issuer("self") // Кто создал токен
                .issuedAt(now) // Когда создан
                .expiresAt(now.plus(1, ChronoUnit.HOURS)) // Когда истечёт (через 1 час)
                .subject(authentication.getName()) // Имя пользователя (например, "favian")
                .claim("scope", scope) // Роли пользователя
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        //**Что происходит:**
        //1. `JwtEncoderParameters.from(claims)` → оборачиваем claims(это данные внутри JWT токена) в параметры
        //2. `this.encoder.encode(...)` → **подписываем токен приватным ключом RSA**
        //3. `.getTokenValue()` → получаем готовую JWT строку
    }
}