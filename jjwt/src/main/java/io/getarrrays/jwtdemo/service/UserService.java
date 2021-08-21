package io.getarrrays.jwtdemo.service;

import io.getarrrays.jwtdemo.domain.AppUser;
import io.getarrrays.jwtdemo.domain.Role;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser appUser);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
