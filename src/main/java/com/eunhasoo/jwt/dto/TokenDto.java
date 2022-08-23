package com.eunhasoo.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Token response DTO
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TokenDto {

    private String token;
}
