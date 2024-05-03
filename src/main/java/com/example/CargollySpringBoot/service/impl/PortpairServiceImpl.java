package com.example.CargollySpringBoot.service.impl;

import com.example.CargollySpringBoot.data.entity.Portpair;
import com.example.CargollySpringBoot.data.repo.PortpairRepo;
import com.example.CargollySpringBoot.model.request.PortpairRequest;
import com.example.CargollySpringBoot.service.PortpairService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;

@Service
public class PortpairServiceImpl implements PortpairService {
    private final PortpairRepo portpairRepo;

    @Autowired
    public PortpairServiceImpl(PortpairRepo portpairRepo) {
        this.portpairRepo = portpairRepo;
    }

    @Override

    public Portpair createPortpair(PortpairRequest portpairRequest) {
        Portpair portpair = new Portpair();
        portpair.setCountry(portpairRequest.getCountry());
        portpair.setLocation(portpairRequest.getLocation());
        portpair.setPortcode(portpairRequest.getPortcode());
        return portpairRepo.save(portpair);
    }

    @Override
    public List<Portpair> getAllPortpair() {
        return portpairRepo.findAll();
    }

    @Override
    @Transactional
    public Portpair updatePortpair(String portcode, PortpairRequest portpairRequest) {
        Portpair portpair = portpairRepo.findByPortcode(portcode);
        if (portpair != null) {
            portpair.setCountry(portpairRequest.getCountry());
            portpair.setLocation(portpairRequest.getLocation());
            portpair.setPortcode(portpairRequest.getPortcode());
            return portpairRepo.save(portpair);
        }
        return null;
    }

    @Override
    @Transactional
    public void deletePortpair(String portcode) {
        Portpair portpair = portpairRepo.findByPortcode(portcode);
        if (portpair != null) {
            portpairRepo.delete(portpair);
        }
    }
}
