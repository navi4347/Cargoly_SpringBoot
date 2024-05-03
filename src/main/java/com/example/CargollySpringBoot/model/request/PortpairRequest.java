package com.example.CargollySpringBoot.model.request;
import com.example.CargollySpringBoot.enums.PortpairRules;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PortpairRequest {
    private String country;
    private String location;
    private String portcode;
}
