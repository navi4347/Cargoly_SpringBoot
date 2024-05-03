package com.example.CargollySpringBoot.data.entity;
import com.example.CargollySpringBoot.service.util.AppConstants;
import com.example.CargollySpringBoot.enums.PortpairRules;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(
        name = AppConstants.TB_PORTPAIR,
        schema = AppConstants.SCHEMA_NAME
)
@Builder
public class Portpair {

    private String country;
    private String location;
    @Id
    private String portcode;
}
