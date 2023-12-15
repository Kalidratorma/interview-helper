package com.kalidratorma.interviewhelper.security.user;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@CrossOrigin
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @GetMapping
    public List<User> readUsers() {
        return userRepository.findAll();
    }

    @PostMapping
    public HttpStatus createUser(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return HttpStatus.CREATED;
    }

    @GetMapping(value = "/{userName}")
    public User readUser(@PathVariable String userName) {
        return userRepository.findByUsername(userName).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND
                        , "Username " + userName + " not found")
        );
    }

    @PutMapping
    public HttpStatus updateUser(@RequestBody User user) {
        User origUser = userRepository.findByUsername(user.getUsername()).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND
                        , "Username " + user.getUsername() + " not found")
        );
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        } else {
            user.setPassword(origUser.getPassword());
        }
        user.setId(origUser.getId());
        userRepository.save(user);
        return HttpStatus.OK;
    }

    @DeleteMapping("/{userName}")
    public HttpStatus deleteUser(@PathVariable String userName) {
        User origUser = userRepository.findByUsername(userName).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND
                        , "Username " + userName + " not found")
        );
        userRepository.deleteById(origUser.getId());
        return HttpStatus.OK;
    }
}
