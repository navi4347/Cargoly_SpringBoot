package com.example.CargollySpringBoot.service;

import com.example.CargollySpringBoot.data.entity.Portpair;
import com.example.CargollySpringBoot.model.request.PortpairRequest;

import java.util.List;

public interface PortpairService {
    Portpair createPortpair(PortpairRequest portpair);
    List<Portpair>getAllPortpair();

    Portpair updatePortpair(String portcode, PortpairRequest portpairRequest);

     void deletePortpair(String portcode);
}
