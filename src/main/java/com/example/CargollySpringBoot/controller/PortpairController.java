package com.example.CargollySpringBoot.controller;

import com.example.CargollySpringBoot.data.entity.Portpair;
import com.example.CargollySpringBoot.data.repo.PortpairRepo;
import com.example.CargollySpringBoot.model.request.PortpairRequest;
import com.example.CargollySpringBoot.service.PortpairService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping("/api")

public class PortpairController {

    @Autowired
    private PortpairService portpairService;

    @Autowired
    private PortpairRepo portpairRepo;

    @GetMapping("/portpair")
    public ResponseEntity<List<Portpair>> getAllPortpairs() {
        List<Portpair> portpairs = portpairService.getAllPortpair();
        return ResponseEntity.ok(portpairs);
    }

    @PostMapping("/portpair")
    public ResponseEntity<Portpair> createPortpair(@RequestBody PortpairRequest portpairRequest) {
        Portpair createdPortpair = portpairService.createPortpair(portpairRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdPortpair);
    }
    @PutMapping("/portpair/{portcode}")
    public ResponseEntity<Portpair> updatePortpair(@PathVariable String portcode, @RequestBody PortpairRequest portpairRequest) {
        return ResponseEntity.ok(portpairService.updatePortpair(portcode, portpairRequest));
    }

    @DeleteMapping("/portpair/{portcode}")
    public ResponseEntity<Void> deletePortpair(@PathVariable String portcode) {
        portpairService.deletePortpair(portcode);
        return ResponseEntity.noContent().build();
    }
}
